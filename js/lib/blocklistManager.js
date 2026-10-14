const path = require('path');
const db = require('../utils/db');
const csvStore = require('./csvStore');
const {
  FIRST_BLOCK_SECONDS,
  evaluateReputation,
  formatBlockReason,
  normalizeReason
} = require('./reputation');

const headers = [
  'id', 'ip_address', 'reason', 'reputation_reason', 'reasons', 'score', 'offenses',
  'blocked_at', 'expires_at', 'duration', 'permanent', 'extended_request_info'
];
const csvPath = process.env.AIWAF_BLOCKED_IPS_CSV_PATH || path.join('logs', 'storage', 'blocked_ips.csv');

let initialized = false;
let dbAvailable = true;

const schemaColumns = {
  reputation_reason: table => table.string('reputation_reason').defaultTo(''),
  reasons: table => table.text('reasons').defaultTo('[]'),
  score: table => table.integer('score').defaultTo(0),
  offenses: table => table.integer('offenses').defaultTo(0),
  expires_at: table => table.float('expires_at').nullable(),
  duration: table => table.integer('duration').nullable(),
  permanent: table => table.boolean('permanent').defaultTo(false),
  extended_request_info: table => table.text('extended_request_info').defaultTo('{}')
};

function parseJson(value, fallback) {
  if (value && typeof value === 'object') return value;
  try { return value ? JSON.parse(value) : fallback; } catch (err) { return fallback; }
}

function toTimestamp(value) {
  if (value === null || value === undefined || value === '') return null;
  const numeric = Number(value);
  if (Number.isFinite(numeric)) return numeric;
  const parsed = new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed / 1000 : null;
}

function normalizeRow(row = {}) {
  const reason = normalizeReason(row.reason || 'legacy block');
  const legacy = !row.reputation_reason;
  return {
    ...row,
    ip_address: String(row.ip_address || row.ip || '').trim(),
    reason,
    reputation_reason: row.reputation_reason || (legacy ? 'legacy_blacklist' : ''),
    reasons: parseJson(row.reasons, legacy ? ['legacy_blacklist', reason] : [reason]),
    score: Number(row.score || (legacy ? 100 : 0)),
    offenses: Number(row.offenses || (legacy ? 1 : 0)),
    blocked_at: toTimestamp(row.blocked_at) || Date.now() / 1000,
    expires_at: toTimestamp(row.expires_at),
    duration: row.duration === '' || row.duration === null || row.duration === undefined ? null : Number(row.duration),
    permanent: row.permanent === true || row.permanent === 1 || String(row.permanent) === '1' || String(row.permanent).toLowerCase() === 'true' || legacy,
    extended_request_info: parseJson(row.extended_request_info, {})
  };
}

function serializeRow(row) {
  return {
    ...row,
    reasons: JSON.stringify(row.reasons || []),
    extended_request_info: JSON.stringify(row.extended_request_info || {}),
    permanent: row.permanent ? 1 : 0
  };
}

function isActive(row, now = Date.now() / 1000) {
  return !!row && (row.permanent || !row.expires_at || Number(row.expires_at) > now);
}

async function ensureDbColumns() {
  if (typeof db.schema.hasColumn !== 'function' || typeof db.schema.table !== 'function') return;
  for (const [name, addColumn] of Object.entries(schemaColumns)) {
    if (!await db.schema.hasColumn('blocked_ips', name)) {
      await db.schema.table('blocked_ips', addColumn);
    }
  }
}

async function initialize() {
  if (initialized) return dbAvailable;

  try {
    const exists = await db.schema.hasTable('blocked_ips');
    if (!exists) {
      await db.schema.createTable('blocked_ips', table => {
        table.increments('id').primary();
        table.string('ip_address').unique().notNullable();
        table.string('reason').defaultTo('WAF blocked');
        table.timestamp('blocked_at').defaultTo(db.fn.now());
        Object.values(schemaColumns).forEach(addColumn => addColumn(table));
      });
    } else {
      await ensureDbColumns();
    }
    dbAvailable = true;
  } catch (err) {
    dbAvailable = false;
  }

  initialized = true;
  return dbAvailable;
}

function csvRows() {
  return csvStore.readRows(csvPath, headers).map(normalizeRow);
}

async function rawRow(ip) {
  const normalizedIp = String(ip || '').trim();
  if (await initialize()) {
    try {
      const row = await db('blocked_ips').where('ip_address', normalizedIp).first();
      return row ? normalizeRow(row) : null;
    } catch (err) {
      dbAvailable = false;
    }
  }
  return csvRows().find(row => row.ip_address === normalizedIp) || null;
}

async function saveRow(row) {
  if (dbAvailable) {
    try {
      const payload = serializeRow(row);
      delete payload.id;
      await db('blocked_ips').insert(payload).onConflict('ip_address').merge();
      return;
    } catch (err) {
      dbAvailable = false;
    }
  }
  await csvStore.updateRows(csvPath, headers, current => {
    const rows = current.map(normalizeRow);
    const index = rows.findIndex(item => item.ip_address === row.ip_address);
    const stored = { ...row, id: index >= 0 ? rows[index].id : csvStore.nextId(rows) };
    if (index >= 0) rows[index] = stored;
    else rows.push(stored);
    return { rows: rows.map(serializeRow) };
  });
}

module.exports = {
  async isBlocked(ip) {
    const row = await rawRow(ip);
    // An expired snapshot is not authority to delete a concurrent refresh.
    return isActive(row);
  },

  async block(ip, reason = 'WAF blocked', options = {}) {
    const normalizedIp = String(ip || '').trim();
    if (!normalizedIp) return false;
    if (options.checkExemptions !== false) {
      try {
        const exemptionStore = require('./exemptionStore');
        if (await exemptionStore.isIpExempt(normalizedIp)) return false;
      } catch (err) {
        // Storage failures must not disable blocking.
      }
    }
    const now = Number(options.now ?? Date.now() / 1000);
    const existing = await rawRow(normalizedIp);
    const decision = evaluateReputation({ existing: existing || {}, reason, now });
    const explicitDuration = options.duration === undefined ? null : Number(options.duration);
    const permanent = options.permanent === true || explicitDuration === 0;
    const duration = permanent ? null : (explicitDuration || decision.duration || FIRST_BLOCK_SECONDS);
    await saveRow({
      ...(existing || {}),
      ip_address: normalizedIp,
      reason: normalizeReason(reason),
      reputation_reason: formatBlockReason(decision),
      reasons: decision.reasons,
      score: decision.score,
      offenses: decision.offenses,
      blocked_at: now,
      expires_at: permanent ? null : now + duration,
      duration,
      permanent,
      extended_request_info: options.extendedRequestInfo || existing?.extended_request_info || {}
    });
    return true;
  },

  blockTemporary(ip, reason, minutes = 60, extendedRequestInfo = {}) {
    return this.block(ip, reason, { duration: Number(minutes) * 60, extendedRequestInfo });
  },

  blockPermanent(ip, reason, extendedRequestInfo = {}) {
    return this.block(ip, reason, { permanent: true, extendedRequestInfo });
  },

  async unblock(ip) {
    const normalizedIp = String(ip || '').trim();
    const useDb = await initialize();
    if (useDb) {
      try {
        const deleted = await db('blocked_ips').where('ip_address', normalizedIp).del();
        return deleted > 0;
      } catch (err) {
        dbAvailable = false;
      }
    }

    return csvStore.updateRows(csvPath, headers, current => {
      const rows = current.map(normalizeRow);
      const filtered = rows.filter(row => row.ip_address !== normalizedIp);
      return { rows: filtered.map(serializeRow), result: filtered.length !== rows.length };
    });
  },

  async getBlockedIPs({ activeOnly = true } = {}) {
    let rows;
    const useDb = await initialize();
    if (useDb) {
      try {
        rows = (await db('blocked_ips').select('*').orderBy('blocked_at', 'desc')).map(normalizeRow);
      } catch (err) {
        dbAvailable = false;
      }
    }
    rows = rows || csvRows().sort((a, b) => b.blocked_at - a.blocked_at);
    return activeOnly ? rows.filter(row => isActive(row)) : rows;
  },

  async getBlockInfo(ip) {
    return rawRow(ip);
  },

  async cleanupExpired(now = Date.now() / 1000) {
    if (await initialize()) {
      try {
        // Evaluate expiry in the DELETE itself, against the current row.
        return await db('blocked_ips').where('permanent', false)
          .whereNotNull('reputation_reason').whereNot('reputation_reason', '')
          .where('expires_at', '>', 0).where('expires_at', '<=', now).del();
      } catch (err) {
        dbAvailable = false;
      }
    }
    return csvStore.updateRows(csvPath, headers, current => {
      const rows = current.map(normalizeRow);
      const active = rows.filter(row => isActive(row, now));
      return { rows: active.map(serializeRow), result: rows.length - active.length };
    });
  },

  async getStatistics() {
    const all = await this.getBlockedIPs({ activeOnly: false });
    const active = all.filter(row => isActive(row));
    const reasonCounts = {};
    active.forEach(row => { reasonCounts[row.reason] = (reasonCounts[row.reason] || 0) + 1; });
    return {
      total: all.length,
      active: active.length,
      expired: all.length - active.length,
      permanent: active.filter(row => row.permanent).length,
      temporary: active.filter(row => !row.permanent).length,
      average_score: active.length ? active.reduce((sum, row) => sum + row.score, 0) / active.length : 0,
      reason_counts: reasonCounts
    };
  },

  async getRecentBlocks(hours = 24) {
    const cutoff = Date.now() / 1000 - Number(hours) * 3600;
    return (await this.getBlockedIPs()).filter(row => row.blocked_at >= cutoff);
  },

  async getTopBlockedReasons(limit = 10) {
    const stats = await this.getStatistics();
    return Object.entries(stats.reason_counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, Number(limit))
      .map(([reason, count]) => ({ reason, count }));
  },

  async bulkBlock(ips, reason, options = {}) {
    const pairs = await Promise.all((ips || []).map(async ip => [ip, await this.block(ip, reason, options)]));
    return Object.fromEntries(pairs);
  },

  async bulkUnblock(ips) {
    const pairs = await Promise.all((ips || []).map(async ip => [ip, await this.unblock(ip)]));
    return Object.fromEntries(pairs);
  },

  async addToAllowlist(ip, reason = 'Manual allowlist') {
    const exemptionStore = require('./exemptionStore');
    await exemptionStore.addIp(ip, reason);
    await this.unblock(ip);
    return true;
  },

  async removeFromAllowlist(ip) {
    return require('./exemptionStore').removeIp(ip);
  },

  async isAllowlisted(ip) {
    return require('./exemptionStore').isIpExempt(ip);
  },

  async getAllowlist() {
    const exemptionStore = require('./exemptionStore');
    return { ips: await exemptionStore.listIps(), paths: await exemptionStore.listPaths() };
  },

  async migrateLegacy({ duration = null, now = Date.now() / 1000 } = {}) {
    const rows = await this.getBlockedIPs({ activeOnly: false });
    let changed = 0;
    for (const original of rows) {
      if (original.reputation_reason && original.reputation_reason !== 'legacy_blacklist') continue;
      const row = normalizeRow(original);
      row.reputation_reason = duration ? 'legacy_blacklist_converted' : 'legacy_blacklist';
      row.permanent = !duration;
      row.duration = duration || null;
      row.expires_at = duration ? Number(now) + Number(duration) : null;
      await saveRow(row);
      changed += 1;
    }
    return { total: rows.length, changed };
  },

  async exportRecords() {
    return this.getBlockedIPs({ activeOnly: false });
  },

  async importRecords(rows = []) {
    let imported = 0;
    for (const raw of rows) {
      const row = normalizeRow(raw);
      if (!row.ip_address) continue;
      await saveRow(row);
      imported += 1;
    }
    return imported;
  },

  async clear() {
    const useDb = await initialize();
    if (useDb) {
      try {
        return await db('blocked_ips').del();
      } catch (err) {
        dbAvailable = false;
      }
    }

    return csvStore.updateRows(csvPath, headers, rows => ({ rows: [], result: rows.length }));
  },

  async initialize() {
    return initialize();
  }
};

// Compatibility method aliases; new applications should use allowlist names.
module.exports.addToWhitelist = module.exports.addToAllowlist;
module.exports.removeFromWhitelist = module.exports.removeFromAllowlist;
module.exports.isWhitelisted = module.exports.isAllowlisted;
module.exports.getWhitelist = module.exports.getAllowlist;
