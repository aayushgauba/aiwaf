const rateLimiter = require('./rateLimiter');
const { createInspector } = require('./sqlInjection');
const blacklistManager = require('./blacklistManager');
const keywordDetector = require('./keywordDetector');
const dynamicKeyword = require('./dynamicKeyword');
const dynamicKeywordStore = require('./dynamicKeywordStore');
const honeypotDetector = require('./honeypotDetector');
const uuidDetector = require('./uuidDetector');
const anomalyDetector = require('./anomalyDetector');
const headerValidation = require('./headerValidation');
const geoBlocker = require('./geoBlocker');
const middlewareLogger = require('./middlewareLogger');
const exemptions = require('./exemptions');
const requestLogStore = require('./requestLogStore');
const { extractExtendedRequestInfo } = require('./runtimeUtils');
const { extractFeatures, init: initFeatureUtils, markRequestStart, STATIC_KW } = require('./featureUtils');
const { normalizeSettings } = require('./settingsCompat');
const {
  createRoutePlan,
  normalizeMiddlewareName
} = require('./pathRules');
const {
  isAutoSelection,
  planEnabledMiddlewares
} = require('./middlewarePlan');
const { getEffectivePathRules } = require('./pathManifest');
const {
  validateHeaders: wasmValidateHeaders,
  validateUrl: wasmValidateUrl,
  validateContent: wasmValidateContent,
  validateRecent: wasmValidateRecent
} = require('./wasmAdapter');

function knownRoutes(app) {
  // Skip route checking if app is undefined (common in proxy setups)
  if (!app) return [];
  const stack = app?._router?.stack || [];
  return stack
    .filter(layer => layer.route && layer.route.path)
    .map(layer => layer.route.path);
}

function matchesKnownRoute(app, path) {
  // In proxy setups, req.app may be undefined or not have routes
  // Return true (treat as known) to skip anomaly detection on proxies
  if (!app || !app._router || !app._router.stack) {
    if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
      console.error(`[AIWAF-ROUTE-CHECK] app=${!!app} app._router=${!!app?._router} returning true (proxy setup)`);
    }
    return true;
  }
  
  const routes = knownRoutes(app);
  
  // If no routes found, assume this is a proxy setup and allow traffic
  if (routes.length === 0) {
    if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
      console.error(`[AIWAF-ROUTE-CHECK] no routes found, returning true (proxy setup)`);
    }
    return true;
  }
  
  const result = routes.some(route => {
    const regex = new RegExp(`^${String(route).replace(/:\\w+/g, '[^/]+')}$`);
    return regex.test(path);
  });
  
  if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
    console.error(`[AIWAF-ROUTE-CHECK] path=${path} matched=${result}`);
  }
  
  return result;
}

function hasUuidRoutes(app) {
  if (!app || !app._router || !app._router.stack) return null;
  const routes = knownRoutes(app);
  if (routes.length === 0) return null;
  return routes.some(route => /(^|[/:{_-])uuid([}/_-]|$)/i.test(String(route)));
}

function shouldReturnJson(req, opts) {
  if (opts.AIWAF_FORCE_JSON_ERRORS) return true;
  const accepts = req.headers?.accept || '';
  const contentType = req.headers?.['content-type'] || '';
  return accepts.includes('application/json') || contentType.includes('application/json') || req.xhr;
}

function normalizeHeaders(rawHeaders) {
  return Object.fromEntries(
    Object.entries(rawHeaders || {}).map(([key, value]) => {
      let normalizedValue = value;
      if (Array.isArray(normalizedValue)) {
        normalizedValue = normalizedValue.join(', ');
      } else if (normalizedValue !== undefined && normalizedValue !== null) {
        normalizedValue = String(normalizedValue);
      }
      return [String(key).toLowerCase(), normalizedValue];
    })
  );
}

function normalizedMiddlewareList(list) {
  if (!Array.isArray(list)) return list;
  return list.map(normalizeMiddlewareName);
}

function applyAutoMiddlewareDefaults(opts, enabled, rawOpts = {}) {
  if (!isAutoSelection(opts.AIWAF_MIDDLEWARES)) return opts;
  const nextOpts = { ...opts };
  const legacy = rawOpts.AIWAF_SETTINGS || {};
  const loggingExplicit = Object.prototype.hasOwnProperty.call(rawOpts, 'AIWAF_MIDDLEWARE_LOGGING')
    || Object.prototype.hasOwnProperty.call(rawOpts, 'middlewareLogging')
    || legacy.logging?.enabled !== undefined
    || process.env.AIWAF_MIDDLEWARE_LOGGING !== undefined;
  const geoExplicit = Object.prototype.hasOwnProperty.call(rawOpts, 'AIWAF_GEO_BLOCK_ENABLED')
    || Object.prototype.hasOwnProperty.call(rawOpts, 'geoBlockEnabled')
    || legacy.geo?.enabled !== undefined
    || process.env.AIWAF_GEO_BLOCK_ENABLED !== undefined;

  if (enabled.has('logging') && !loggingExplicit) {
    nextOpts.AIWAF_MIDDLEWARE_LOGGING = true;
  }
  if (enabled.has('geo_block') && !geoExplicit) {
    nextOpts.AIWAF_GEO_BLOCK_ENABLED = true;
  }
  return nextOpts;
}


module.exports = function aiwaf(rawOpts = {}) {
  if (rawOpts.AIWAF_NATIVE_PIPELINE !== undefined) {
    if (Object.keys(rawOpts).some(key => key !== 'AIWAF_NATIVE_PIPELINE')) {
      throw new Error('Native pipeline uses a dedicated profile; do not mix legacy options');
    }
    const ready = require('./nativePipeline')(rawOpts.AIWAF_NATIVE_PIPELINE);
    // Compatibility wrapper for framework adapters. Await ready during application startup.
    // No legacy modules are initialized and no fallback is selected on this branch.
    const middleware = async (req, res, next) => (await ready)(req, res, next);
    middleware.ready = ready;
    middleware.inspectPayload = async req => (await ready).inspectPayload(req);
    return middleware;
  }
  let opts = normalizeSettings(rawOpts);
  const inspectSql = createInspector(opts);
  opts.AIWAF_MIDDLEWARES = normalizedMiddlewareList(opts.AIWAF_MIDDLEWARES);
  opts.AIWAF_DISABLE_MIDDLEWARES = normalizedMiddlewareList(opts.AIWAF_DISABLE_MIDDLEWARES) || [];
  const pathRules = getEffectivePathRules(opts.AIWAF_PATH_RULES, { manifestPath: opts.AIWAF_PATH_MANIFEST });

  let enabledMiddlewares = planEnabledMiddlewares({
    orderedAvailable: [
      'geo_block',
      'ip_keyword_block',
      'rate_limit',
      'ai_anomaly',
      'honeypot',
      'uuid_tamper',
      'header_validation',
      'logging'
    ],
    requested: opts.AIWAF_MIDDLEWARES,
    disabled: opts.AIWAF_DISABLE_MIDDLEWARES,
    accessLog: opts.AIWAF_ACCESS_LOG,
    geoEnabledFlag: !!opts.AIWAF_GEO_BLOCK_ENABLED,
    staticBlockCountries: opts.AIWAF_GEO_BLOCK_COUNTRIES || [],
    dynamicBlockCountries: [],
    hasUuidRoutes: null
  });
  opts = applyAutoMiddlewareDefaults(opts, enabledMiddlewares, rawOpts);

  rateLimiter.init(opts);
  keywordDetector.init(opts);
  dynamicKeyword.init(opts);
  honeypotDetector.init(opts);
  uuidDetector.init(opts);
  anomalyDetector.init(opts);
  initFeatureUtils(opts);
  headerValidation.init(opts);
  geoBlocker.init(opts);
  middlewareLogger.init(opts);
  exemptions.init(opts);

  if (opts.AIWAF_CLEAR_STATE_ON_START) {
    Promise.allSettled([
      blacklistManager.clear(),
      requestLogStore.clear(),
      dynamicKeywordStore.clear()
    ]).catch(() => {});
  }

  const inspectPayload = async req => {
    const path = String(req.path || req.url || '/').split('?')[0].toLowerCase();
    const ip = req.headers?.['x-forwarded-for']?.split(',')[0].trim() || req.ip;
    const plan = createRoutePlan(path, pathRules, req.aiwafRoute || {});
    if (!enabledMiddlewares.has('ip_keyword_block') || !plan.shouldApply('ip_keyword_block')
        || await exemptions.isExemptRequest(ip, path)) return null;
    const finding = inspectSql(req);
    if (finding?.mode === 'monitor') {
      (opts.logger || console).warn?.({ event: 'aiwaf.payload', rule: finding.rule, mode: finding.mode });
      return null;
    }
    return finding;
  };
  const middleware = async (req, res, next) => {
    const ipHdr = req.headers['x-forwarded-for'];
    const ip = ipHdr ? ipHdr.split(',')[0].trim() : req.ip;
    const path = String(req.path || req.url || '/').toLowerCase();
    const method = String(req.method || 'GET').toUpperCase();
    if (isAutoSelection(opts.AIWAF_MIDDLEWARES)) {
      enabledMiddlewares = planEnabledMiddlewares({
        orderedAvailable: [
          'geo_block',
          'ip_keyword_block',
          'rate_limit',
          'ai_anomaly',
          'honeypot',
          'uuid_tamper',
          'header_validation',
          'logging'
        ],
        requested: opts.AIWAF_MIDDLEWARES,
        disabled: opts.AIWAF_DISABLE_MIDDLEWARES,
        accessLog: opts.AIWAF_ACCESS_LOG,
        geoEnabledFlag: !!opts.AIWAF_GEO_BLOCK_ENABLED,
        staticBlockCountries: opts.AIWAF_GEO_BLOCK_COUNTRIES || [],
        dynamicBlockCountries: [],
        hasUuidRoutes: hasUuidRoutes(req.app)
      });
    }
    const routePlan = createRoutePlan(path, pathRules, req.aiwafRoute || {});
    const shouldApply = name => enabledMiddlewares.has(normalizeMiddlewareName(name)) && routePlan.shouldApply(name);
    const blockIp = reason => blacklistManager.block(ip, reason, {
      extendedRequestInfo: extractExtendedRequestInfo(req, {
        enabled: opts.AIWAF_CAPTURE_EXTENDED_REQUEST_INFO,
        maxHeaders: opts.AIWAF_EXTENDED_INFO_MAX_HEADERS,
        maxValueLength: opts.AIWAF_EXTENDED_INFO_MAX_VALUE_LENGTH
      }) || {}
    });
    
    // Debug: Log first character of path to ensure it's being captured
    if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
      console.error(`[AIWAF-DEBUG] method=${method} path=${path} req.path=${req.path} req.url=${req.url} ip=${ip} req.ip=${req.ip} x-forwarded-for=${ipHdr}`);
    }

    if (shouldApply('logging')) {
      middlewareLogger.attach(req, res, { ip });
    }
    markRequestStart(req);

    const deny = (status, code, reason, country = '') => {
      middlewareLogger.markBlocked(res, reason || code, country);
      if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
        console.error(`[AIWAF-BLOCK] status=${status} code=${code} reason=${reason} ip=${ip}`);
      }
      if (shouldReturnJson(req, opts)) {
        res.status(status).json({ error: code });
      } else {
        res.status(status).send(code);
      }
    };

    if (opts.AIWAF_METHOD_POLICY_ENABLED === true) {
      const allowed = (opts.AIWAF_ALLOWED_METHODS || ['GET', 'POST', 'HEAD', 'OPTIONS'])
        .map(m => String(m).toUpperCase());
      if (!allowed.includes(method)) {
        if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
          console.error(`[AIWAF-BLOCK-METHOD] method=${method} not in allowed=${allowed.join(',')}`);
        }
        await blockIp(`method_not_allowed:${method}`);
        return deny(405, 'blocked', `method_not_allowed:${method}`);
      }
    }

    if (await exemptions.isExemptRequest(ip, path)) {
      if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
        console.error(`[AIWAF-EXEMPT] path=${path}`);
      }
      return next();
    }

    if (shouldApply('ip_keyword_block') && await blacklistManager.isBlocked(ip)) {
      if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
        console.error(`[AIWAF-BLOCK-BLACKLIST] ip=${ip}`);
      }
      return deny(403, 'blocked', 'blacklist');
    }

    const payloadFinding = await inspectPayload(req);
    if (payloadFinding) return deny(payloadFinding.status, payloadFinding.rule, payloadFinding.rule);

    if (shouldApply('header_validation')) {
      const headerReason = headerValidation.validate(req);
      if (headerReason) {
        if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
          console.error(`[AIWAF-BLOCK-HEADER] reason=${headerReason}`);
        }
        await blockIp(headerReason);
        return deny(403, 'blocked', headerReason);
      }
    }

    const headerValidationApplies = shouldApply('header_validation');
    const ipKeywordApplies = shouldApply('ip_keyword_block');
    const wasmValidationEnabled = opts.AIWAF_WASM_VALIDATION !== false && (headerValidationApplies || ipKeywordApplies);
    const wasmHeaderValidationEnabled = opts.AIWAF_WASM_HEADER_VALIDATION !== false;
    if (wasmValidationEnabled) {
      const pathForHeaders = req.path || req.url || '';
      const wasmConfig = headerValidation.getWasmConfig(req.method);
      const shouldSkipWasmHeaders = headerValidation.isStaticRequest(pathForHeaders);
      const headerWasmReason = (shouldSkipWasmHeaders || !wasmHeaderValidationEnabled || !headerValidationApplies)
        ? null
        : await wasmValidateHeaders(normalizeHeaders(req.headers || {}), wasmConfig);
      if (headerWasmReason) {
        if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
          console.error(`[AIWAF-BLOCK-WASM-HEADER] reason=${headerWasmReason}`);
        }
        await blockIp(`wasm_header:${headerWasmReason}`);
        return deny(403, 'blocked', `wasm_header:${headerWasmReason}`);
      }

      if (ipKeywordApplies) {
        const host = req.headers?.host || '';
        const urlPath = req.originalUrl || req.url || '/';
        const protocol = req.protocol || (req.headers?.['x-forwarded-proto'] || 'http');
        const fullUrl = host ? `${protocol}://${host}${urlPath}` : urlPath;
        const urlWasmReason = await wasmValidateUrl(fullUrl);
        if (urlWasmReason) {
          if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
            console.error(`[AIWAF-BLOCK-WASM-URL] reason=${urlWasmReason}`);
          }
          await blockIp(`wasm_url:${urlWasmReason}`);
          return deny(403, 'blocked', `wasm_url:${urlWasmReason}`);
        }

        if (req.body !== undefined && req.body !== null) {
          let content = req.body;
          if (Buffer.isBuffer(content)) {
            content = content.toString('utf8');
          } else if (typeof content === 'object') {
            try {
              content = JSON.stringify(content);
            } catch (err) {
              content = String(content);
            }
          } else {
            content = String(content);
          }

          if (content && content.length) {
            const contentWasmReason = await wasmValidateContent(content);
            if (contentWasmReason) {
              if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
                console.error(`[AIWAF-BLOCK-WASM-CONTENT] reason=${contentWasmReason}`);
              }
              await blockIp(`wasm_content:${contentWasmReason}`);
              return deny(403, 'blocked', `wasm_content:${contentWasmReason}`);
            }
          }
        }
      }

      if (opts.AIWAF_WASM_VALIDATE_RECENT && shouldApply('ai_anomaly')) {
        const recentRows = await requestLogStore.recent(200);
        const recent = recentRows
          .filter(row => row.ip_address === ip)
          .map(row => ({ path: row.path, status: Number(row.status || 0) }));
        if (recent.length) {
          const recentWasmReason = await wasmValidateRecent(recent);
          if (recentWasmReason) {
            if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
              console.error(`[AIWAF-BLOCK-WASM-RECENT] reason=${recentWasmReason}`);
            }
            await blockIp(`wasm_recent:${recentWasmReason}`);
            return deny(403, 'blocked', `wasm_recent:${recentWasmReason}`);
          }
        }
      }
    }

    if (shouldApply('geo_block')) {
      const geoResult = await geoBlocker.check(req);
      if (geoResult.blocked) {
        if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
          console.error(`[AIWAF-BLOCK-GEO] reason=${geoResult.reason}`);
        }
        await blockIp(geoResult.reason || 'geo_block');
        return deny(403, 'blocked', geoResult.reason || 'geo_block', geoResult.country);
      }
    }

    if (shouldApply('honeypot')) {
      const honeypotResult = honeypotDetector.evaluate(req, ip, path);
      if (honeypotResult.triggered) {
        if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
          console.error(`[AIWAF-BLOCK-HONEYPOT] reason=${honeypotResult.reason}`);
        }
        await blockIp(honeypotResult.reason || 'honeypot');
        const status = honeypotResult.statusCode || 403;
        const code = honeypotResult.errorCode || 'bot_detected';
        return deny(status, code, honeypotResult.reason || 'honeypot');
      }
    }

    if (shouldApply('rate_limit')) {
      try {
        const rateOverrides = routePlan.getOverrides('RATE_LIMIT');
        await rateLimiter.record(ip, rateOverrides);

        if (await rateLimiter.isBlocked(ip, rateOverrides)) {
          if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
            console.error(`[AIWAF-BLOCK-RATE] ip=${ip}`);
          }
          if (await blacklistManager.isBlocked(ip)) {
            return deny(403, 'blocked', 'flood_or_blacklist');
          }
          return deny(429, 'too_many_requests', 'rate_limit');
        }
      } catch (error) {
        if (error.code === 'AIWAF_RATE_CACHE_UNAVAILABLE') {
          return deny(503, 'temporarily_unavailable', 'rate_cache_unavailable');
        }
        throw error;
      }
    }

    if (shouldApply('ip_keyword_block')) {
      const staticMatch = await keywordDetector.checkAccelerated(path);
      if (staticMatch && !exemptions.shouldSkipKeyword(staticMatch, path)) {
        if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
          console.error(`[AIWAF-BLOCK-STATIC-KW] match=${staticMatch}`);
        }
        await blockIp(`static:${staticMatch}`);
        return deny(403, 'blocked', `static:${staticMatch}`);
      }

      const dynamicMatch = await dynamicKeyword.checkAccelerated(path);
      if (dynamicMatch && !exemptions.shouldSkipKeyword(dynamicMatch, path)) {
        if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
          console.error(`[AIWAF-BLOCK-DYNAMIC-KW] match=${dynamicMatch}`);
        }
        await blockIp(`dynamic:${dynamicMatch}`);
        return deny(403, 'blocked', `dynamic:${dynamicMatch}`);
      }
    }

    if (shouldApply('uuid_tamper') && await uuidDetector.isSuspicious(req)) {
      if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
        console.error(`[AIWAF-BLOCK-UUID]`);
      }
      await blockIp('uuid');
      return deny(403, 'blocked', 'uuid');
    }

    if (shouldApply('ai_anomaly') && !matchesKnownRoute(req.app, req.path || req.url || '/')) {
      if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
        console.error(`[AIWAF-ANOMALY-CHECK] path=${req.path || req.url} has no known route`);
      }
      const features = await extractFeatures(req);
      const isAnomaly = await anomalyDetector.isAnomalous(features);
      if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
        console.error(`[AIWAF-ANOMALY-RESULT] isAnomaly=${isAnomaly} hasModel=${anomalyDetector.hasModel()} isSufficient=${anomalyDetector.isModelSufficientlyTrained()}`);
      }
      if (isAnomaly && anomalyDetector.isModelSufficientlyTrained()) {
        // Analyze recent behavior before blocking.
        const now = Date.now();
        const recentData = (await requestLogStore.recent(5000))
          .filter(row => row.ip_address === ip)
          .map(row => ({
            timestamp: row.created_at ? new Date(row.created_at).getTime() : now,
            path: row.path,
            status: Number(row.status || 0),
            responseTime: Number(row.response_time_ms || 0)
          }))
          .filter(entry => now - entry.timestamp <= 5 * 60 * 1000);

        const stats = await anomalyDetector.analyzeRecentBehaviorAccelerated(recentData);
        if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
          console.error(`[AIWAF-ANOMALY-STATS] should_block=${stats?.should_block}`);
        }
        if (stats && stats.should_block) {
          const reason = `AI anomaly + scanning 404s (total:${stats.max_404s}, scanning:${stats.scanning_404s}, kw:${stats.avg_kw_hits.toFixed(1)}, burst:${stats.avg_burst.toFixed(1)})`;
          if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
            console.error(`[AIWAF-ANOMALY-BLOCKING] reason=${reason}`);
          }
          await blockIp(reason);
          return deny(403, 'blocked', 'anomaly');
        }
      } else if (!anomalyDetector.isModelSufficientlyTrained()) {
        // No sufficient model - skip aggressive anomaly detection
        // Fallback is disabled until we have at least 10k training samples
        if (process.env.AIWAF_DEBUG_MIDDLEWARE) {
          console.error(`[AIWAF-ANOMALY-FALLBACK-DISABLED] No sufficiently trained model available - skipping fallback`);
        }
      }
    }

    res.on('finish', () => {
      const statusCode = Number(res.statusCode || 0);
      anomalyDetector.maybeLearnKeyword(req.path || req.url || '', statusCode, opts);
    });

    next();
  };
  middleware.inspectPayload = inspectPayload;
  return middleware;
};
