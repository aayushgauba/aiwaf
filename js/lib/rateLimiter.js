const NodeCache = require('node-cache');
const blocklistManager = require('./blocklistManager');

let cacheBackend;
let opts;
let cleanupInterval;

function unavailable() {
  const error = new Error('Rate cache unavailable');
  error.code = 'AIWAF_RATE_CACHE_UNAVAILABLE';
  return error;
}

const defaultMemoryCache = new NodeCache({ stdTTL: 60, checkperiod: 120 }); // Auto cleanup every 2 minutes

const fallbackCache = {
  lPush: async (key, value) => {
    const arr = defaultMemoryCache.get(key) || [];
    arr.unshift(value);
    defaultMemoryCache.set(key, arr, opts.WINDOW_SEC * 2); // Keep for 2x window duration
  },
  expire: (key, ttl) => Promise.resolve(defaultMemoryCache.ttl(key, ttl)),
  lLen: async (key) => {
    const arr = defaultMemoryCache.get(key) || [];
    return arr.length;
  },
  lRange: async (key, start, end) => {
    const arr = defaultMemoryCache.get(key) || [];
    const normalizedEnd = end < 0 ? arr.length - 1 : end;
    return arr.slice(start, normalizedEnd + 1);
  }
};

// Additional cleanup for old timestamps within arrays
function cleanupOldTimestamps() {
  const now = Date.now();
  const cutoff = now - (opts.WINDOW_SEC * 2 * 1000); // Keep 2x window worth

  const keys = defaultMemoryCache.keys();
  for (const key of keys) {
    if (key.startsWith('ratelimit:')) {
      const arr = defaultMemoryCache.get(key);
      if (Array.isArray(arr)) {
        const filtered = arr.filter(timestamp => timestamp > cutoff);
        if (filtered.length !== arr.length) {
          if (filtered.length > 0) {
            defaultMemoryCache.set(key, filtered, opts.WINDOW_SEC * 2);
          } else {
            defaultMemoryCache.del(key);
          }
        }
      }
    }
  }
}

function getEffectiveOpts(overrides = {}) {
  const windowSec = Number(
    overrides.WINDOW_SEC
      ?? overrides.WINDOW
      ?? overrides.window_seconds
      ?? overrides.windowSeconds
      ?? opts.WINDOW_SEC
  );
  const maxReq = Number(
    overrides.MAX_REQ
      ?? overrides.MAX
      ?? overrides.max_requests
      ?? overrides.maxRequests
      ?? opts.MAX_REQ
  );
  const floodReq = Number(
    overrides.FLOOD_REQ
      ?? overrides.FLOOD
      ?? overrides.flood_threshold
      ?? overrides.floodThreshold
      ?? opts.FLOOD_REQ
  );

  return {
    WINDOW_SEC: Number.isFinite(windowSec) ? windowSec : opts.WINDOW_SEC,
    MAX_REQ: Number.isFinite(maxReq) ? maxReq : opts.MAX_REQ,
    FLOOD_REQ: Number.isFinite(floodReq) ? floodReq : opts.FLOOD_REQ
  };
}

module.exports = {
  async init(o) {
    opts = {
      WINDOW_SEC: o?.WINDOW_SEC ?? 60,
      MAX_REQ: o?.MAX_REQ ?? 100,
      FLOOD_REQ: o?.FLOOD_REQ ?? 200,
      failureMode: o?.AIWAF_RATE_CACHE_FAILURE_MODE ?? 'closed',
      cache: o?.cache
    };
    const requiredOps = ['lPush', 'expire', 'lLen', 'lRange'];
    const externalCache = opts.cache;
    const hasRequiredOps = externalCache && requiredOps.every(op => typeof externalCache[op] === 'function');
    if (!['closed', 'open'].includes(opts.failureMode)) throw new Error('AIWAF_RATE_CACHE_FAILURE_MODE must be closed or open');
    cacheBackend = hasRequiredOps ? externalCache : fallbackCache;

    // Start cleanup interval for fallback cache
    if (cacheBackend === fallbackCache && !cleanupInterval) {
      cleanupInterval = setInterval(cleanupOldTimestamps, 60000); // Cleanup every minute
      if (typeof cleanupInterval.unref === 'function') {
        cleanupInterval.unref();
      }
      console.log('Rate limiter memory cleanup enabled');
    }
  },

  async record(ip, overrides = {}) {
    const now = Date.now().toString();
    const effective = getEffectiveOpts(overrides);

    try {
      const key = `ratelimit:${ip}`;
      await cacheBackend.lPush(key, now);
      await cacheBackend.expire(key, effective.WINDOW_SEC * 2); // Extended TTL
      const count = await cacheBackend.lLen(key);
      if (count > effective.FLOOD_REQ) {
        await blocklistManager.block(ip, 'flood');
      }
    } catch (err) {
      console.warn('Rate cache unavailable in record().');
      if (opts.failureMode === 'closed') throw unavailable();
    }
  },

  async isBlocked(ip, overrides = {}) {
    const effective = getEffectiveOpts(overrides);
    try {
      if (await blocklistManager.isBlocked(ip)) return true;
    } catch (err) {
      console.warn('Blocklist unavailable during rate check.');
      if (opts.failureMode === 'closed') throw unavailable();
    }

    try {
      const key = `ratelimit:${ip}`;
      const now = Date.now();
      const timestamps = (await cacheBackend.lRange(key, 0, -1)).map(Number);
      const within = timestamps.filter(t => now - t < effective.WINDOW_SEC * 1000);
      return within.length > effective.MAX_REQ;
    } catch (err) {
      console.warn('Rate cache unavailable in isBlocked().');
      if (opts.failureMode === 'closed') throw unavailable();
      return false; // Fail open
    }
  },

  cleanupExpired: cleanupOldTimestamps,

  // Cleanup method for graceful shutdown
  cleanup() {
    if (cleanupInterval) {
      clearInterval(cleanupInterval);
      cleanupInterval = null;
    }
    if (defaultMemoryCache && typeof defaultMemoryCache.close === 'function') {
      defaultMemoryCache.close();
    }
  }
};
