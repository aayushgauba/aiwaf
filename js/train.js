const fs = require('fs');
const path = require('path');
const glob = require('glob');
const zlib = require('zlib');
const readline = require('readline');
const { createIsolationForest } = require('./lib/wasmAdapter');
const requestLogStore = require('./lib/requestLogStore');
const modelStore = require('./lib/modelStore');
const blacklistManager = require('./lib/blacklistManager');
const { calculateTrainingFeatures } = require('./lib/trainingFeatures');
const { withTrainingEvidence } = require('./lib/trainingEvidence');
const TRAINING_STATE_DIR = process.env.AIWAF_TRAINING_STATE_DIR
  || path.dirname(process.env.AIWAF_BLOCKED_IPS_CSV_PATH || path.join('logs', 'storage', 'blocked_ips.csv'));

const STATIC_KW = [
  '.php', '.xmlrpc', 'wp-', '.env', '.git', '.bak',
  'conflg', 'shell', 'filemanager'
];

const STATUS_IDX = ['200', '403', '404', '500'];

const LOG_PATH = process.env.AIWAF_ACCESS_LOG || process.env.NODE_LOG_PATH || '/var/log/nginx/access.log';
const LOG_GLOB = process.env.NODE_LOG_GLOB || `${LOG_PATH}.*`;
const MIDDLEWARE_LOG_PATH = process.env.AIWAF_MIDDLEWARE_LOG_PATH || path.join(__dirname, 'logs', 'aiwaf-requests.jsonl');
const MIDDLEWARE_LOG_CSV_PATH = process.env.AIWAF_MIDDLEWARE_LOG_CSV_PATH || path.join(__dirname, 'logs', 'aiwaf-requests.csv');
const MIN_TRAIN_LOGS = Number(process.env.AIWAF_MIN_TRAIN_LOGS || 50);
const MIN_AI_LOGS = Number(process.env.AIWAF_MIN_AI_LOGS || 10000);
const FORCE_TRAINING = ['1', 'true', 'yes', 'on'].includes(String(process.env.AIWAF_FORCE_AI_TRAINING || '').toLowerCase());
const ENABLE_KEYWORD_LEARNING = ['1', 'true', 'yes', 'on'].includes(String(process.env.AIWAF_ENABLE_KEYWORD_LEARNING ?? 'true').toLowerCase());
const DYNAMIC_TOP_N = Number(process.env.AIWAF_DYNAMIC_TOP_N || 10);

const LINE_RX = /(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\].*?"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (.*?) HTTP\/.*?" (\d{3}).*?(?:response-time=(\d+\.\d+)|$)/;

async function* readLines(file) {
  const stream = file.endsWith('.gz')
    ? fs.createReadStream(file).pipe(zlib.createGunzip())
    : fs.createReadStream(file);
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  for await (const line of rl) {
    yield line;
  }
}

async function readAccessLogLines() {
  const lines = [];

  if (fs.existsSync(LOG_PATH)) {
    for await (const line of readLines(LOG_PATH)) {
      lines.push(line);
    }
  }

  for (const rotatedPath of glob.sync(LOG_GLOB)) {
    for await (const line of readLines(rotatedPath)) {
      lines.push(line);
    }
  }

  return lines;
}

async function readMiddlewareEvents() {
  if (!fs.existsSync(MIDDLEWARE_LOG_PATH)) return [];

  const events = [];
  for await (const line of readLines(MIDDLEWARE_LOG_PATH)) {
    const raw = String(line || '').trim();
    if (!raw) continue;

    try {
      const event = JSON.parse(raw);
      events.push(event);
    } catch (err) {
      // Ignore malformed lines.
    }
  }

  return events;
}

async function readMiddlewareCsvEvents() {
  if (!fs.existsSync(MIDDLEWARE_LOG_CSV_PATH)) return [];

  const events = [];
  let isFirstLine = true;
  for await (const line of readLines(MIDDLEWARE_LOG_CSV_PATH)) {
    const raw = String(line || '').trim();
    if (!raw) continue;
    if (isFirstLine) {
      isFirstLine = false;
      if (raw.toLowerCase().startsWith('timestamp,')) {
        continue;
      }
    }

    const parts = raw.match(/("([^"]|"")*"|[^,]+)/g) || [];
    const unquote = val => {
      const trimmed = String(val || '').trim();
      if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
        return trimmed.slice(1, -1).replace(/""/g, '"');
      }
      return trimmed;
    };

    events.push({
      timestamp: unquote(parts[0] || ''),
      ip: unquote(parts[1] || ''),
      method: unquote(parts[2] || ''),
      path: unquote(parts[3] || ''),
      status: unquote(parts[4] || ''),
      responseTime: unquote(parts[5] || '')
    });
  }

  return events;
}

async function readDbRequestLogs() {
  try {
    const rows = await requestLogStore.recent(20000);
    return rows.map(row => ({
      ip: row.ip_address,
      path: row.path,
      status: row.status,
      responseTime: row.response_time_ms,
      timestamp: row.created_at
    }));
  } catch (err) {
    return [];
  }
}

function getDynamicKeywordStore() {
  // Lazy require for easier test mocking.
  // eslint-disable-next-line global-require
  return require('./lib/dynamicKeywordStore');
}

function getExemptionStore() {
  // Lazy require for easier test mocking.
  // eslint-disable-next-line global-require
  return require('./lib/exemptionStore');
}

function normalizeTokens(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(v => String(v).toLowerCase());
  return String(value)
    .split(',')
    .map(v => v.trim().toLowerCase())
    .filter(Boolean);
}

const LOGIN_PATH_PREFIXES = normalizeTokens(process.env.AIWAF_LOGIN_PATH_PREFIXES || '/admin/login/,/login/,/accounts/login/,/auth/login/,/signin/');
const PACKAGED_GEO_MMDB_PATH = path.resolve(__dirname, 'geolock', 'ipinfo_lite.mmdb');
const MONOREPO_GEO_MMDB_PATH = path.resolve(
  __dirname,
  '..',
  'py',
  'aiwaf',
  'core',
  'geolock',
  'ipinfo_lite.mmdb'
);
const GEO_MMDB_PATH = process.env.AIWAF_GEO_MMDB_PATH
  ? path.resolve(process.env.AIWAF_GEO_MMDB_PATH)
  : (fs.existsSync(PACKAGED_GEO_MMDB_PATH) ? PACKAGED_GEO_MMDB_PATH : MONOREPO_GEO_MMDB_PATH);

let geoReader = null;
function loadGeoReader() {
  if (geoReader || !fs.existsSync(GEO_MMDB_PATH)) return geoReader;
  try {
    // Optional dependency
    // eslint-disable-next-line global-require, import/no-extraneous-dependencies
    const maxmind = require('maxmind');
    geoReader = maxmind.openSync(GEO_MMDB_PATH);
  } catch (err) {
    geoReader = null;
  }
  return geoReader;
}

function lookupCountry(ip) {
  const reader = loadGeoReader();
  if (!reader) return null;
  try {
    const result = reader.get(ip);
    return result?.country?.iso_code || result?.registered_country?.iso_code || null;
  } catch (err) {
    return null;
  }
}

async function getExemptPaths() {
  const fromEnv = normalizeTokens(process.env.AIWAF_EXEMPT_PATHS);
  const fromDb = [];
  try {
    const exemptionStore = getExemptionStore();
    await exemptionStore.initialize();
    const rows = await exemptionStore.listPaths(1000);
    rows.forEach(row => fromDb.push(String(row.path_prefix || '').toLowerCase()));
  } catch (err) {
    // ignore
  }
  return Array.from(new Set([...fromEnv, ...fromDb]));
}

async function removeExemptKeywords() {
  const exemptTokens = new Set();
  const exemptPaths = await getExemptPaths();
  exemptPaths.forEach(pathVal => {
    String(pathVal || '')
      .split(/\W+/)
      .filter(seg => seg.length > 3)
      .forEach(seg => exemptTokens.add(seg.toLowerCase()));
  });

  normalizeTokens(process.env.AIWAF_EXEMPT_KEYWORDS).forEach(token => exemptTokens.add(token));
  normalizeTokens(process.env.AIWAF_ALLOWED_PATH_KEYWORDS).forEach(token => exemptTokens.add(token));

  for (const token of exemptTokens) {
    const dynamicKeywordStore = getDynamicKeywordStore();
    await dynamicKeywordStore.remove(token);
  }

  if (exemptTokens.size > 0) {
    console.log(`Removed ${exemptTokens.size} exempt keywords from learning`);
  }
}

async function unblockExemptIps() {
  try {
    const exemptionStore = getExemptionStore();
    await exemptionStore.initialize();
    const rows = await exemptionStore.listIps();
    const ips = rows.map(row => row.ip_address).filter(Boolean);
    if (ips.length === 0) return;
    for (const ip of ips) {
      await blacklistManager.unblock(ip);
    }
    console.log(`Cleared ${ips.length} exempt IPs from blacklist`);
  } catch (err) {
    // ignore
  }
}

function getLegitimateKeywords() {
  const defaults = new Set([
    'profile', 'user', 'users', 'account', 'accounts', 'settings', 'dashboard',
    'home', 'about', 'contact', 'help', 'search', 'list', 'lists',
    'view', 'views', 'edit', 'create', 'update', 'delete', 'detail', 'details',
    'api', 'auth', 'login', 'logout', 'register', 'signup', 'signin',
    'reset', 'confirm', 'activate', 'verify', 'page', 'pages',
    'category', 'categories', 'tag', 'tags', 'post', 'posts',
    'article', 'articles', 'blog', 'blogs', 'news', 'item', 'items',
    'admin', 'administration', 'manage', 'manager', 'control', 'panel',
    'config', 'configuration', 'option', 'options', 'preference', 'preferences',
    'token', 'tokens', 'oauth', 'social', 'rest', 'framework', 'cors',
    'debug', 'toolbar', 'extensions', 'allauth', 'crispy', 'forms',
    'channels', 'celery', 'redis', 'cache', 'email', 'mail',
    'endpoint', 'endpoints', 'resource', 'resources', 'data', 'export',
    'import', 'upload', 'download', 'file', 'files', 'media', 'images',
    'documents', 'reports', 'analytics', 'stats', 'statistics',
    'customer', 'customers', 'client', 'clients', 'company', 'companies',
    'department', 'departments', 'employee', 'employees', 'team', 'teams',
    'project', 'projects', 'task', 'tasks', 'event', 'events',
    'notification', 'notifications', 'alert', 'alerts',
    'language', 'languages', 'locale', 'locales', 'translation', 'translations',
    'en', 'fr', 'de', 'es', 'it', 'pt', 'ru', 'ja', 'zh', 'ko'
  ]);

  normalizeTokens(process.env.AIWAF_ALLOWED_PATH_KEYWORDS).forEach(token => defaults.add(token));
  normalizeTokens(process.env.AIWAF_EXEMPT_KEYWORDS).forEach(token => defaults.add(token));
  return defaults;
}

function isMaliciousContext(path, keyword, status = '404') {
  if (!path || !keyword) return false;
  const pathLower = String(path).toLowerCase();

  const indicators = [
    pathLower.includes('../') || pathLower.includes('..\\'),
    pathLower.includes('.env') || pathLower.includes('wp-admin') || pathLower.includes('phpmyadmin'),
    pathLower.includes('backup') || pathLower.includes('database') || pathLower.includes('mysql'),
    pathLower.includes('passwd') || pathLower.includes('shadow') || pathLower.includes('xmlrpc'),
    pathLower.includes('shell') || pathLower.includes('cmd') || pathLower.includes('exec') || pathLower.includes('eval'),
    pathLower.includes('union+select') || pathLower.includes('<script') || pathLower.includes('javascript:'),
    pathLower.includes('%2e%2e') || pathLower.includes('%252e') || pathLower.includes('%c0%ae') || pathLower.includes('%3c%73%63%72%69%70%74'),
    status === '404' && (pathLower.length > 50 || (pathLower.match(/\//g) || []).length > 10),
    status === '404' && /[<>{}$`]/.test(pathLower)
  ];

  return indicators.some(Boolean);
}

function extractLegitimateFromLogs(parsedRequests) {
  const legitimate = new Set();
  for (const record of parsedRequests) {
    const status = String(record.status || '');
    if (!status.startsWith('2') && !status.startsWith('3')) continue;
    const pathLower = String(record.path || '').toLowerCase();
    for (const seg of pathLower.split(/\W+/)) {
      if (seg.length > 2) legitimate.add(seg);
    }
  }
  return legitimate;
}

function summarizeGeo(ips, title) {
  if (!ips || ips.length === 0) return;
  const counts = new Map();
  let unknown = 0;
  for (const ip of ips) {
    const code = lookupCountry(ip);
    if (!code) {
      unknown += 1;
      continue;
    }
    counts.set(code, (counts.get(code) || 0) + 1);
  }
  if (counts.size === 0 && unknown === 0) return;

  const top = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 10);
  console.log(title);
  top.forEach(([code, count]) => {
    console.log(`  - ${code}: ${count}`);
  });
  if (unknown) {
    console.log(`  - UNKNOWN: ${unknown}`);
  }
}

function parseLogLine(line) {
  const match = LINE_RX.exec(line);
  if (!match) return null;

  const ip = match[1];
  const timestampStr = match[2];
  const uri = match[3].split('?')[0];
  const status = match[4];
  const rt = match[5] ? parseFloat(match[5]) : 0.0;

  let timestamp = new Date(NaN);
  try {
    const cleanTimestamp = timestampStr.split(' ')[0];
    const monthMap = {
      Jan: '01', Feb: '02', Mar: '03', Apr: '04',
      May: '05', Jun: '06', Jul: '07', Aug: '08',
      Sep: '09', Oct: '10', Nov: '11', Dec: '12'
    };

    const parts = cleanTimestamp.split(/[/:\s]/);
    if (parts.length >= 6) {
      const [day, monthText, year, hour, minute, second] = parts;
      const month = monthMap[monthText];
      if (!month) return null;
      const offset = timestampStr.trim().split(/\s+/)[1] || '+0000';
      if (!/^[+-]\d{4}$/.test(offset)) return null;
      timestamp = new Date(`${year}-${month}-${day}T${hour}:${minute}:${second}${offset.slice(0, 3)}:${offset.slice(3)}`);
    }
  } catch (err) {
    return null;
  }
  if (!Number.isFinite(timestamp.getTime())) return null;

  return {
    ip,
    path: uri,
    status,
    responseTime: rt,
    timestamp
  };
}

function parseMiddlewareEvent(event) {
  if (!event || !event.path || !event.ip) return null;
  const timestamp = new Date(event.timestamp);
  if (!event.timestamp || !Number.isFinite(timestamp.getTime())) return null;

  return {
    ip: String(event.ip),
    path: String(event.path).split('?')[0],
    status: String(event.status || 200),
    responseTime: Number(event.responseTime || 0),
    timestamp
  };
}

function parseDbEvent(event) {
  if (!event || !event.path || !event.ip) return null;
  const timestamp = new Date(event.timestamp);
  if (!event.timestamp || !Number.isFinite(timestamp.getTime())) return null;
  return {
    ip: String(event.ip),
    path: String(event.path).split('?')[0],
    status: String(event.status || 200),
    responseTime: Number(event.responseTime || 0),
    timestamp
  };
}

async function train() {
  return withTrainingEvidence(TRAINING_STATE_DIR, async evidence => {
    const rawAccessLines = await readAccessLogLines();
    let parsedRequests = rawAccessLines.map(parseLogLine).filter(Boolean);

    if (parsedRequests.length === 0) {
      const middlewareEvents = await readMiddlewareEvents();
      parsedRequests = middlewareEvents.map(parseMiddlewareEvent).filter(Boolean);

      if (parsedRequests.length > 0) {
        console.log(`Using middleware logs from ${MIDDLEWARE_LOG_PATH} (${parsedRequests.length} records)`);
      }
    }

    if (parsedRequests.length === 0) {
      const csvEvents = await readMiddlewareCsvEvents();
      parsedRequests = csvEvents.map(parseMiddlewareEvent).filter(Boolean);
      if (parsedRequests.length > 0) {
        console.log(`Using middleware CSV logs from ${MIDDLEWARE_LOG_CSV_PATH} (${parsedRequests.length} records)`);
      }
    }

    if (parsedRequests.length === 0) {
      const dbEvents = await readDbRequestLogs();
      parsedRequests = dbEvents.map(parseDbEvent).filter(Boolean);
      if (parsedRequests.length > 0) {
        console.log(`Using request_logs table (${parsedRequests.length} records)`);
      }
    }

    if (parsedRequests.length === 0) {
      console.warn('No logs found. Set NODE_LOG_PATH or enable AIWAF middleware logging.');
      return;
    }

    // Unstable/missing timestamps cannot establish fresh evidence on a replay.
    parsedRequests = parsedRequests.filter(record => Number.isFinite(record.timestamp.getTime()));
    const freshRequests = evidence.fresh(parsedRequests);
    await unblockExemptIps();

    const ip404Counts = new Map();
    const ip404LoginCounts = new Map();
    const ipTimes = new Map();
    for (const record of freshRequests) {
      const ts = record.timestamp instanceof Date ? record.timestamp.getTime() : new Date(record.timestamp).getTime();
      if (!ipTimes.has(record.ip)) ipTimes.set(record.ip, []);
      ipTimes.get(record.ip).push(ts);

      if (String(record.status) !== '404') continue;
      const pathLower = String(record.path || '').toLowerCase();
      const isLogin = LOGIN_PATH_PREFIXES.some(prefix => pathLower.startsWith(prefix));
      const map = isLogin ? ip404LoginCounts : ip404Counts;
      map.set(record.ip, (map.get(record.ip) || 0) + 1);
    }

    for (const [ip, count] of ip404Counts.entries()) {
      if (count >= 6) {
        const loginCount = ip404LoginCounts.get(ip) || 0;
        if (count > loginCount) {
          await evidence.block(ip, () => blacklistManager.block(ip, `Excessive 404s (non-login ${count}/${count + loginCount})`));
        }
      }
    }

    if (parsedRequests.length < MIN_TRAIN_LOGS && !FORCE_TRAINING) {
      console.warn(`Insufficient logs (${parsedRequests.length}) < AIWAF_MIN_TRAIN_LOGS (${MIN_TRAIN_LOGS}). Set AIWAF_FORCE_AI_TRAINING=true to override.`);
      return;
    }

    console.log(`Parsed ${parsedRequests.length} valid requests`);

    const features = await calculateTrainingFeatures(parsedRequests, STATIC_KW, STATUS_IDX);
    if (features.length === 0) {
      console.warn('No features generated.');
      return;
    }

    console.log(`Generated ${features.length} feature vectors`);

    await removeExemptKeywords();
    const legitimateFromLogs = extractLegitimateFromLogs(parsedRequests);

    let anomalyIps = new Set();
    if (parsedRequests.length >= MIN_AI_LOGS || FORCE_TRAINING) {
      const model = await createIsolationForest({ nTrees: 100, sampleSize: 256 });
      model.fit(features);

      const metadata = {
        createdAt: new Date().toISOString(),
        samplesCount: features.length,
        featureCount: 6,
        version: '1.1'
      };
      const modelData = model.__aiwafWasm
        ? { model_type: 'aiwaf_wasm.IsolationForest', model_state: model.toJSON(), metadata }
        : { ...model.toJSON(), metadata };

      await modelStore.save(process.env, modelData, modelData.metadata);
      console.log(`Trained on ${features.length} samples`);

      // Identify anomalous IPs and optionally block if suspicious.
      const anomaliesByIp = new Map();
      const enforcementFeatures = freshRequests.length ? await calculateTrainingFeatures(freshRequests, STATIC_KW, STATUS_IDX) : [];
      freshRequests.forEach((record, idx) => {
        const feature = enforcementFeatures[idx];
        if (!feature) return;
        const isAnomaly = model.isAnomaly(feature, 0.5);
        if (!isAnomaly) return;
        const ip = record.ip;
        if (!anomaliesByIp.has(ip)) anomaliesByIp.set(ip, []);
        anomaliesByIp.get(ip).push(record);
      });

      anomalyIps = new Set(anomaliesByIp.keys());
      if (anomalyIps.size > 0) {
        console.log(`Detected ${anomalyIps.size} potentially anomalous IPs`);
        summarizeGeo(Array.from(anomalyIps), 'Geo summary for anomalous IPs (top 10):');
      }

      for (const [ip, records] of anomaliesByIp.entries()) {
        const totalRequests = records.length;
        const max404s = records.reduce((sum, r) => sum + (String(r.status) === '404' ? 1 : 0), 0);
        const avgKwHits = records.reduce((sum, r) => {
          const pathLower = String(r.path || '').toLowerCase();
          return sum + STATIC_KW.reduce((acc, kw) => acc + (pathLower.includes(kw) ? 1 : 0), 0);
        }, 0) / totalRequests;
        const bursts = (ipTimes.get(ip) || []).filter(ts => Date.now() - ts <= 10000).length;
        const avgBurst = totalRequests ? bursts / totalRequests : 0;

        if (max404s === 0 && avgKwHits === 0) {
          continue;
        }
        if (avgKwHits < 2 && max404s < 10 && avgBurst < 15 && totalRequests < 100) {
          continue;
        }
        await evidence.block(ip, () => blacklistManager.block(ip, `AI anomaly + suspicious patterns (kw:${avgKwHits.toFixed(1)}, 404s:${max404s}, burst:${avgBurst.toFixed(1)})`));
      }
    } else {
      console.log(`AI training skipped: ${parsedRequests.length} logs < ${MIN_AI_LOGS}`);
    }

    if (ENABLE_KEYWORD_LEARNING) {
      const legitimate = new Set([...getLegitimateKeywords(), ...legitimateFromLogs]);
      const tokens = new Map();
      for (const record of parsedRequests) {
        const status = String(record.status || '');
        if (!status.startsWith('4') && !status.startsWith('5')) continue;
        const pathLower = String(record.path || '').toLowerCase();
        for (const seg of pathLower.split(/\W+/)) {
          if (seg.length <= 3) continue;
          if (STATIC_KW.includes(seg)) continue;
          if (legitimate.has(seg)) continue;
          if (!isMaliciousContext(pathLower, seg, status)) continue;
          tokens.set(seg, (tokens.get(seg) || 0) + 1);
        }
      }

      const ranked = Array.from(tokens.entries()).sort((a, b) => b[1] - a[1]).slice(0, DYNAMIC_TOP_N);
      for (const [kw, count] of ranked) {
        const dynamicKeywordStore = getDynamicKeywordStore();
        await dynamicKeywordStore.add(kw, count);
      }

      console.log(`Learned ${ranked.length} dynamic keywords`);
    } else {
      console.log('Keyword learning disabled via AIWAF_ENABLE_KEYWORD_LEARNING');
    }

    try {
      const blocked = await blacklistManager.getBlockedIPs();
      summarizeGeo(blocked.map(row => row.ip_address).filter(Boolean), 'Geo summary for blocked IPs (top 10):');
    } catch (err) {
      // ignore
    }
  });
}

module.exports = train;
async function runCLI() {
  try {
    await train();
    process.exitCode = 0;
  } catch (error) {
    console.error('Training failed:', error);
    process.exitCode = 1;
  }
}
module.exports.runCLI = runCLI;
if (require.main === module) runCLI();
