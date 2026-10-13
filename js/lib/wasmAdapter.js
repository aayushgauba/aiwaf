const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const { IsolationForest } = require('./isolationForest');
let wasmModule = null;
let wasmLoadAttempted = false;
let wasmLoadError = null;

async function loadWasmFromDisk() {
  const pkgDir = path.join(__dirname, '..', 'node_modules', 'aiwaf-wasm');
  const wasmPath = path.join(pkgDir, 'aiwaf_wasm_bg.wasm');
  const bgPath = path.join(pkgDir, 'aiwaf_wasm_bg.js');

  if (!fs.existsSync(wasmPath) || !fs.existsSync(bgPath)) {
    return null;
  }

  const bg = await import(pathToFileURL(bgPath).href);
  const bytes = fs.readFileSync(wasmPath);
  const importObject = { './aiwaf_wasm_bg.js': bg };
  const { instance } = await WebAssembly.instantiate(bytes, importObject);

  if (typeof bg.__wbg_set_wasm === 'function') {
    bg.__wbg_set_wasm(instance.exports);
  }
  if (instance.exports && typeof instance.exports.__wbindgen_start === 'function') {
    instance.exports.__wbindgen_start();
  }

  return {
    AiwafIsolationForest: bg.IsolationForest,
    IsolationForest: bg.IsolationForest,
    KeywordMatcher: bg.KeywordMatcher,
    RouteMatcher: bg.RouteMatcher,
    validate_headers: bg.validate_headers,
    validate_headers_with_config: bg.validate_headers_with_config,
    validate_url: bg.validate_url,
    validate_content: bg.validate_content,
    analyze_recent_behavior: bg.analyze_recent_behavior,
    extract_features: bg.extract_features,
    extract_training_features: bg.extract_training_features,
    extract_raw_training_features: bg.extract_raw_training_features,
    extract_features_batch_with_state: bg.extract_features_batch_with_state,
    finalize_feature_state: bg.finalize_feature_state,
    build_records: bg.build_records,
    rust_payload_from_records: bg.rust_payload_from_records,
    python_feature_from_record: bg.python_feature_from_record,
    python_features_batched: bg.python_features_batched,
    NativeRequestPipeline: bg.NativeRequestPipeline
  };
}

async function loadWasmFromPackageModule() {
  const pkgDir = path.join(__dirname, '..', 'node_modules', 'aiwaf-wasm');
  const modulePath = path.join(pkgDir, 'aiwaf_wasm.js');
  if (!fs.existsSync(modulePath)) return null;
  try {
    return await import(pathToFileURL(modulePath).href);
  } catch (err) {
    return null;
  }
}

async function loadWasm() {
  if (wasmLoadAttempted) return wasmModule;
  wasmLoadAttempted = true;
  if (process.env.AIWAF_DISABLE_WASM === '1') {
    wasmModule = null;
    return wasmModule;
  }
  try {
    // Optional dependency: aiwaf-wasm
    // eslint-disable-next-line global-require, import/no-extraneous-dependencies
    const mod = require('aiwaf-wasm');
    if (mod) {
      if (typeof mod.default === 'function') {
        await mod.default();
      } else if (typeof mod.init === 'function') {
        await mod.init();
      }
      wasmModule = mod;
    }
  } catch (err) {
    try {
      const fallback = await loadWasmFromPackageModule() || await loadWasmFromDisk();
      if (fallback) {
        wasmModule = fallback;
      } else {
        wasmLoadError = err;
        wasmModule = null;
      }
    } catch (fallbackErr) {
      wasmLoadError = fallbackErr || err;
      wasmModule = null;
    }
  }
  return wasmModule;
}

async function createIsolationForest(opts = {}) {
  const mod = await loadWasm();
  const WasmIsolationForest = mod && (mod.AiwafIsolationForest || mod.IsolationForest);
  if (typeof WasmIsolationForest === 'function') {
    const nTrees = Number.isFinite(Number(opts.nTrees)) ? Number(opts.nTrees) : 100;
    const sampleSize = Number.isFinite(Number(opts.sampleSize)) ? Number(opts.sampleSize) : 256;
    const threshold = Number.isFinite(Number(opts.threshold)) ? Number(opts.threshold) : 0.5;
    const seed = Number.isFinite(Number(opts.seed)) ? Number(opts.seed) : 42;
    const wasmModel = new WasmIsolationForest({
      n_trees: nTrees,
      n_estimators: nTrees,
      sample_size: sampleSize,
      max_samples: sampleSize,
      threshold,
      seed,
      random_state: seed
    });

    return {
      fit(data) {
        return wasmModel.fit(data);
      },
      retrain(data) {
        if (typeof wasmModel.retrain === 'function') {
          return wasmModel.retrain(data);
        }
        return undefined;
      },
      anomalyScore(point) {
        if (typeof wasmModel.anomaly_score === 'function') {
          return wasmModel.anomaly_score(point);
        }
        if (typeof wasmModel.anomalyScore === 'function') {
          return wasmModel.anomalyScore(point);
        }
        return 0;
      },
      isAnomaly(point, thresh = threshold) {
        if (typeof wasmModel.is_anomaly === 'function') {
          return wasmModel.is_anomaly(point, thresh);
        }
        const score = this.anomalyScore(point);
        return score > thresh;
      },
      scoreSamples(data) {
        if (typeof wasmModel.score_samples === 'function') {
          return wasmModel.score_samples(data);
        }
        return Array.isArray(data) ? data.map(point => this.anomalyScore(point)) : [];
      },
      decisionFunction(data) {
        if (typeof wasmModel.decision_function === 'function') {
          return wasmModel.decision_function(data);
        }
        return this.scoreSamples(data);
      },
      predict(data) {
        if (typeof wasmModel.predict === 'function') {
          return wasmModel.predict(data);
        }
        return this.scoreSamples(data).map(score => (score > threshold ? -1 : 1));
      },
      toJSON() {
        if (typeof wasmModel.to_json === 'function') {
          return wasmModel.to_json();
        }
        return null;
      },
      __aiwafWasm: true
    };
  }

  return new IsolationForest(opts);
}

async function createIsolationForestFromJSON(state) {
  const mod = await loadWasm();
  const WasmIsolationForest = mod && (mod.AiwafIsolationForest || mod.IsolationForest);
  if (WasmIsolationForest && typeof WasmIsolationForest.from_json === 'function') {
    try {
      const wasmModel = WasmIsolationForest.from_json(state);
      return {
        fit(data) {
          return wasmModel.fit(data);
        },
        retrain(data) {
          return typeof wasmModel.retrain === 'function' ? wasmModel.retrain(data) : undefined;
        },
        anomalyScore(point) {
          return typeof wasmModel.anomaly_score === 'function' ? wasmModel.anomaly_score(point) : 0;
        },
        isAnomaly(point, thresh = 0.5) {
          if (typeof wasmModel.is_anomaly === 'function') return wasmModel.is_anomaly(point, thresh);
          return this.anomalyScore(point) > thresh;
        },
        scoreSamples(data) {
          return typeof wasmModel.score_samples === 'function' ? wasmModel.score_samples(data) : [];
        },
        decisionFunction(data) {
          return typeof wasmModel.decision_function === 'function' ? wasmModel.decision_function(data) : this.scoreSamples(data);
        },
        predict(data) {
          return typeof wasmModel.predict === 'function' ? wasmModel.predict(data) : [];
        },
        toJSON() {
          return typeof wasmModel.to_json === 'function' ? wasmModel.to_json() : state;
        },
        __aiwafWasm: true
      };
    } catch (err) {
      // Fall back to JS model parsing below.
    }
  }
  return IsolationForest.fromJSON(state);
}

function normalizeValidationResult(result, fallbackReason) {
  if (result === null || result === undefined || result === true || result === 0) return null;
  if (result === false) return fallbackReason;
  if (typeof result === 'string') return result || null;
  if (typeof result === 'object') {
    if (result.ok === false) return result.reason || fallbackReason;
    if (result.allowed === false) return result.reason || fallbackReason;
  }
  return null;
}

function normalizeRecentEntries(entries = []) {
  return (Array.isArray(entries) ? entries : []).map(entry => {
    const hasMilliseconds = entry.timestamp_ms !== undefined && entry.timestamp_ms !== null;
    const rawTimestamp = Number(hasMilliseconds ? entry.timestamp_ms : (entry.timestamp ?? entry.timestamp_epoch ?? Date.now()));
    const timestamp = (hasMilliseconds || rawTimestamp > 1000000000000) ? rawTimestamp / 1000 : rawTimestamp;
    return {
      path_lower: String(entry.path_lower || entry.path || '').toLowerCase(),
      timestamp: Number.isFinite(timestamp) ? timestamp : Date.now() / 1000,
      status: Number(entry.status || entry.status_code || 0),
      kw_check: entry.kw_check !== false
    };
  });
}

function normalizeHeaderValue(value) {
  if (value === undefined || value === null) return '';
  return String(value);
}

function toPlainHeaderObject(headers) {
  const out = {};
  if (!headers) return out;
  if (typeof headers.forEach === 'function' && typeof headers.get === 'function') {
    headers.forEach((value, key) => {
      if (!key) return;
      out[String(key).toLowerCase()] = normalizeHeaderValue(value);
    });
    return out;
  }
  for (const [key, value] of Object.entries(headers || {})) {
    if (!key) continue;
    const normalizedValue = Array.isArray(value)
      ? value.map(v => normalizeHeaderValue(v)).join(', ')
      : normalizeHeaderValue(value);
    out[String(key).toLowerCase()] = normalizedValue;
  }
  return out;
}

async function validateHeaders(headers, config) {
  const mod = await loadWasm();
  if (!mod || typeof mod.validate_headers !== 'function') return null;
  try {
    const headerObject = toPlainHeaderObject(headers);
    if (process.env.AIWAF_DEBUG_WASM_HEADERS) {
      // eslint-disable-next-line no-console
      console.error(`[WASM-HEADER-VALIDATION] headers keys: ${Object.keys(headerObject || {}).join(', ')}`);
      // eslint-disable-next-line no-console
      console.error(`[WASM-HEADER-VALIDATION] user-agent: ${headerObject?.['user-agent'] || ''}`);
      // eslint-disable-next-line no-console
      console.error(`[WASM-HEADER-VALIDATION] accept: ${headerObject?.['accept'] || ''}`);
    }
    let result;
    const forcePlain = process.env.AIWAF_FORCE_PLAIN_HEADERS === '1';
    const allowHeaders = process.env.AIWAF_USE_HEADERS === '1';
    const canUseHeaders = allowHeaders
      && !forcePlain
      && (typeof window !== 'undefined' && typeof Headers === 'function');

    const src = headerObject || {};
    const headerInputObj = { ...src };
    if (src['user-agent'] && !headerInputObj.HTTP_USER_AGENT) {
      headerInputObj.HTTP_USER_AGENT = src['user-agent'];
    }
    if (src.accept && !headerInputObj.HTTP_ACCEPT) {
      headerInputObj.HTTP_ACCEPT = src.accept;
    }
    if (src['accept-language'] && !headerInputObj.HTTP_ACCEPT_LANGUAGE) {
      headerInputObj.HTTP_ACCEPT_LANGUAGE = src['accept-language'];
    }
    if (src['accept-encoding'] && !headerInputObj.HTTP_ACCEPT_ENCODING) {
      headerInputObj.HTTP_ACCEPT_ENCODING = src['accept-encoding'];
    }
    if (src.connection && !headerInputObj.HTTP_CONNECTION) {
      headerInputObj.HTTP_CONNECTION = src.connection;
    }
    if (src['cache-control'] && !headerInputObj.HTTP_CACHE_CONTROL) {
      headerInputObj.HTTP_CACHE_CONTROL = src['cache-control'];
    }

    const headerInput = canUseHeaders ? new Headers(src) : headerInputObj;
    if (config && typeof mod.validate_headers_with_config === 'function') {
      const required = (config.requiredHeaders && config.requiredHeaders.length) ? config.requiredHeaders : null;
      const minScore = Number.isFinite(Number(config.minScore)) ? Number(config.minScore) : null;
      result = mod.validate_headers_with_config(headerInput, required, minScore);
    } else {
      result = mod.validate_headers(headerInput);
    }
    if (process.env.AIWAF_DEBUG_WASM_HEADERS) {
      // eslint-disable-next-line no-console
      console.error(`[WASM-HEADER-VALIDATION] raw=${JSON.stringify(result)}`);
    }
    return normalizeValidationResult(result, 'wasm_header_invalid');
  } catch (err) {
    if (process.env.AIWAF_DEBUG_WASM_HEADERS) {
      // eslint-disable-next-line no-console
      console.error(`[WASM-HEADER-VALIDATION] error=${err?.message || err}`);
    }
    return 'wasm_header_error';
  }
}

async function validateUrl(url) {
  const mod = await loadWasm();
  if (!mod || typeof mod.validate_url !== 'function') return null;
  try {
    const result = mod.validate_url(url);
    return normalizeValidationResult(result, 'wasm_url_invalid');
  } catch (err) {
    return 'wasm_url_error';
  }
}

async function validateContent(content) {
  const mod = await loadWasm();
  if (!mod || typeof mod.validate_content !== 'function') return null;
  try {
    const result = mod.validate_content(content);
    return normalizeValidationResult(result, 'wasm_content_invalid');
  } catch (err) {
    return 'wasm_content_error';
  }
}

async function validateRecent(recent) {
  const mod = await loadWasm();
  if (mod && typeof mod.validate_recent === 'function') {
    try {
      const result = mod.validate_recent(recent);
      return normalizeValidationResult(result, 'wasm_recent_invalid');
    } catch (err) {
      return 'wasm_recent_error';
    }
  }
  if (!mod || typeof mod.analyze_recent_behavior !== 'function') return null;
  try {
    const result = mod.analyze_recent_behavior(normalizeRecentEntries(recent), []);
    if (result && typeof result === 'object' && result.should_block === true) {
      return 'wasm_recent_invalid';
    }
    return null;
  } catch (err) {
    return 'wasm_recent_error';
  }
}

async function analyzeRecentBehavior(entries, staticKeywords = []) {
  const mod = await loadWasm();
  if (!mod || typeof mod.analyze_recent_behavior !== 'function') return null;
  try {
    return mod.analyze_recent_behavior(normalizeRecentEntries(entries), staticKeywords || []);
  } catch (err) {
    return null;
  }
}

async function extractWasmFeatures(records, staticKeywords = []) {
  const mod = await loadWasm();
  if (!mod || typeof mod.extract_features !== 'function') return null;
  try {
    return mod.extract_features(records || [], staticKeywords || []);
  } catch (err) {
    return null;
  }
}

async function extractWasmTrainingFeatures(records, staticKeywords = []) {
  const mod = await loadWasm();
  if (!mod || typeof mod.extract_training_features !== 'function') return null;
  try {
    return mod.extract_training_features(records || [], staticKeywords || []);
  } catch (err) {
    return null;
  }
}

async function extractWasmRawTrainingFeatures(records, staticKeywords = [], statusIndices = []) {
  const mod = await loadWasm();
  if (!mod || typeof mod.extract_raw_training_features !== 'function') return null;
  try {
    return mod.extract_raw_training_features(records || [], staticKeywords || [], statusIndices || []);
  } catch (err) {
    return null;
  }
}

async function createKeywordMatcher(keywords = []) {
  const mod = await loadWasm();
  if (!mod || typeof mod.KeywordMatcher !== 'function') return null;
  try {
    const matcher = new mod.KeywordMatcher(keywords);
    return {
      firstMatch(path) {
        return matcher.first_match(path) || null;
      }
    };
  } catch (err) {
    return null;
  }
}

async function createRouteMatcher(prefixes = []) {
  const mod = await loadWasm();
  if (!mod || typeof mod.RouteMatcher !== 'function') return null;
  try {
    const matcher = new mod.RouteMatcher(prefixes);
    return {
      matchIndex(path) {
        const index = matcher.match_index(path);
        return Number.isInteger(index) ? index : null;
      }
    };
  } catch (err) {
    return null;
  }
}

async function extractWasmFeaturesBatchWithState(records, staticKeywords = [], state = null) {
  const mod = await loadWasm();
  if (!mod || typeof mod.extract_features_batch_with_state !== 'function') return null;
  try {
    return mod.extract_features_batch_with_state(records || [], staticKeywords || [], state);
  } catch (err) {
    return null;
  }
}

async function finalizeWasmFeatureState() {
  const mod = await loadWasm();
  if (!mod || typeof mod.finalize_feature_state !== 'function') return null;
  try {
    return mod.finalize_feature_state();
  } catch (err) {
    return null;
  }
}

async function buildWasmRecords(parsed, ip404, pathExistsFn, pathExemptFn, statusIdxList) {
  const mod = await loadWasm();
  if (!mod || typeof mod.build_records !== 'function') return null;
  try {
    return mod.build_records(
      parsed || [],
      ip404 || {},
      typeof pathExistsFn === 'function' ? pathExistsFn : (() => false),
      typeof pathExemptFn === 'function' ? pathExemptFn : (() => false),
      statusIdxList || []
    );
  } catch (err) {
    return null;
  }
}

async function rustPayloadFromRecords(records) {
  const mod = await loadWasm();
  if (!mod || typeof mod.rust_payload_from_records !== 'function') return null;
  try {
    return mod.rust_payload_from_records(records || []);
  } catch (err) {
    return null;
  }
}

async function pythonFeatureFromRecord(record, ipTimes = {}, staticKeywords = []) {
  const mod = await loadWasm();
  if (!mod || typeof mod.python_feature_from_record !== 'function') return null;
  try {
    return mod.python_feature_from_record(record, ipTimes, staticKeywords);
  } catch (err) {
    return null;
  }
}

async function pythonFeaturesBatched(records, ipTimes = {}, staticKeywords = [], options = {}) {
  const mod = await loadWasm();
  if (!mod || typeof mod.python_features_batched !== 'function') return null;
  try {
    return mod.python_features_batched(
      records || [],
      ipTimes || {},
      staticKeywords || [],
      null,
      Number.isFinite(Number(options.batchSize)) ? Number(options.batchSize) : 1000,
      options.parallelEnabled !== false,
      Number.isFinite(Number(options.parallelChunkSize)) ? Number(options.parallelChunkSize) : 1000,
      Number.isFinite(Number(options.maxWorkers)) ? Number(options.maxWorkers) : 0
    );
  } catch (err) {
    return null;
  }
}

function getWasmStatus() {
  return {
    loaded: !!(wasmModule && (wasmModule.AiwafIsolationForest || wasmModule.IsolationForest)),
    error: wasmLoadError ? String(wasmLoadError.message || wasmLoadError) : null
  };
}

async function createRequestPipeline(profile = {}, model = null) {
  const mod = await loadWasm();
  if (!mod || typeof mod.NativeRequestPipeline !== 'function') {
    throw new Error('Native pipeline requires aiwaf-wasm with NativeRequestPipeline support; no fallback');
  }
  const native = new mod.NativeRequestPipeline(JSON.stringify(profile));
  if (['begin','finish','inspect_payload','inspect_body','set_model','clear_model','diagnostics'].some(name => typeof native[name] !== 'function')) {
    native.free();
    throw new Error('Incompatible NativeRequestPipeline API; install the matching WASM build');
  }
  const setModel = value => {
    if (value == null) { native.clear_model(); return; }
    if (!value.__aiwafWasm || typeof value.toJSON !== 'function') throw new TypeError('A trained Rust/WASM model is required');
    const Forest = mod.IsolationForest || mod.AiwafIsolationForest;
    const snapshot = Forest.from_json(value.toJSON());
    try { native.set_model(snapshot); } finally { snapshot.free(); }
  };
  try { if (model) setModel(model); } catch (error) { native.free(); throw error; }
  return { native, setModel };
}

module.exports = {
  createRequestPipeline,
  createIsolationForest,
  createIsolationForestFromJSON,
  validateHeaders,
  validateUrl,
  validateContent,
  validateRecent,
  analyzeRecentBehavior,
  extractWasmFeatures,
  extractWasmTrainingFeatures,
  extractWasmRawTrainingFeatures,
  createKeywordMatcher,
  createRouteMatcher,
  extractWasmFeaturesBatchWithState,
  finalizeWasmFeatureState,
  buildWasmRecords,
  rustPayloadFromRecords,
  pythonFeatureFromRecord,
  pythonFeaturesBatched,
  getWasmStatus
};
