// Explicit WASM-owned request engine. Node owns transport and immediate filesystem I/O.
const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const { createRequestPipeline } = require('./wasmAdapter');
const { ALL_MIDDLEWARES, normalizeMiddlewareName } = require('./pathRules');

const LOG_HEADER = 'timestamp,ip,method,path,status,response_time_ms,blocked,reason,country,user_agent\n';
const BLOCK_HEADER = 'ip,expires_at,reason\n';
const KEYWORD_HEADER = 'keyword\n';
const DEFER_BODY = Symbol('aiwaf.native.defer-body');
function writer(file, header, durable) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (fs.existsSync(file) && fs.statSync(file).size) {
    const fd = fs.openSync(file, 'r');
    try {
      const bytes = Buffer.alloc(Buffer.byteLength(header));
      fs.readSync(fd, bytes, 0, bytes.length, 0);
      if (bytes.toString() !== header) throw new Error(`Incompatible native CSV schema: ${file}`);
    } finally { fs.closeSync(fd); }
  }
  const fd = fs.openSync(file, 'a');
  const append = row => {
    const buffer = Buffer.from(row);
    let offset = 0;
    while (offset < buffer.length) {
      const written = fs.writeSync(fd, buffer, offset, buffer.length - offset);
      if (!written) throw new Error('Native CSV append made no progress');
      offset += written;
    }
    if (durable) fs.fsyncSync(fd);
  };
  try { if (!fs.statSync(file).size) append(header); } catch (error) { fs.closeSync(fd); throw error; }
  return { append, close() { fs.closeSync(fd); } };
}
// Startup only: quoted newlines and commas must round-trip persisted native CSV.
function readRows(file, expected) {
  const text = fs.readFileSync(file, 'utf8');
  const rows = []; let row = [], value = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      if (quoted && text[i + 1] === '"') { value += '"'; i++; }
      else quoted = !quoted;
    } else if (!quoted && (ch === ',' || ch === '\n')) {
      row.push(value); value = '';
      if (ch === '\n') { rows.push(row); row = []; }
    } else value += ch;
  }
  if (quoted || row.length || value) throw new Error('Incomplete native policy CSV');
  if (rows.shift()?.join(',') !== expected.join(',')) throw new Error('Invalid native policy schema');
  return rows.map(cells => {
    if (cells.length !== expected.length) throw new Error('Invalid native policy CSV row');
    return Object.fromEntries(expected.map((key, index) => [key, cells[index]]));
  });
}
function safeBody(req, limit) {
  const body = req.body;
  if (body === undefined) {
    // Require a bounded parser before this adapter when a body is present.
    return { body: null, exhausted: Number(req.headers?.['content-length'] || 0) > 0 || !!req.headers?.['transfer-encoding'] };
  }
  if (body && typeof body.pipe === 'function') return { body: null, exhausted: true };
  try {
    const value = Buffer.isBuffer(body) ? body.toString('utf8') : body;
    const encoded = JSON.stringify(value);
    if (encoded === undefined || Buffer.byteLength(encoded) > limit * 8) return { body: null, exhausted: true };
    return { body: value, exhausted: false };
  } catch (_) { return { body: null, exhausted: true }; }
}
function headers(raw = {}) {
  return Object.fromEntries(Object.entries(raw).map(([key, value]) => [
    ['content-type', 'content-length'].includes(key.toLowerCase()) ? key.toUpperCase().replace(/-/g, '_') : `HTTP_${key.toUpperCase().replace(/-/g, '_')}`,
    Array.isArray(value) ? value.join(', ') : String(value ?? '')
  ]));
}
function synchronous(callback, req, fallback) {
  const result = callback ? callback(req) : fallback;
  if (result && typeof result.then === 'function') throw new TypeError('Native fact callbacks must return synchronous values');
  return result;
}

module.exports = async function createNativeMiddleware(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('Native adapter options must be an object');
  if (options.profile !== undefined && (!options.profile || typeof options.profile !== 'object' || Array.isArray(options.profile))) throw new TypeError('Native profile must be an object');
  const allowed = new Set(['profile', 'dataDir', 'logPath', 'logFsync', 'persistBlocks', 'model', 'countryLookup', 'authenticated', 'routeExists', 'onError']);
  for (const key of Object.keys(options)) if (!allowed.has(key)) throw new Error(`Unknown native adapter option: ${key}`);
  for (const key of ['countryLookup','authenticated','routeExists','onError']) {
    if (options[key] != null && (typeof options[key] !== 'function' || options[key].constructor.name === 'AsyncFunction')) throw new TypeError(`${key} must be synchronous`);
  }
  const profile = JSON.parse(JSON.stringify(options.profile || {}));
  if (!Object.hasOwn(profile, 'blocklist') && Object.hasOwn(profile, 'blacklist')) profile.blocklist = profile.blacklist;
  delete profile.blacklist;
  const dataDir = path.resolve(options.dataDir || 'aiwaf_native_data');
  // State files are dedicated to this adapter. Legacy ORM/CSV schemas are not mixed.
  const blockPath = path.join(dataDir, 'native_blocks.csv');
  const keywordPath = path.join(dataDir, 'native_keywords.csv');
  const persist = options.persistBlocks !== false;
  const opened = [];
  let log, blocks, keywords, engine;
  try {
    if (persist) {
      blocks = writer(blockPath, BLOCK_HEADER, true); opened.push(blocks);
      keywords = writer(keywordPath, KEYWORD_HEADER, true); opened.push(keywords);
      const blocklist = { ...(profile.blocklist || {}) };
      for (const row of readRows(blockPath, ['ip','expires_at','reason'])) {
        if (!row.ip || !row.expires_at || !Number.isFinite(Number(row.expires_at))) throw new Error('Invalid persisted block row');
        blocklist[row.ip] = Number(row.expires_at);
      }
      profile.blocklist = blocklist;
      profile.dynamic_keywords = [...new Set([...(profile.dynamic_keywords || []), ...readRows(keywordPath, ['keyword']).map(r => r.keyword)])];
    }
    engine = await createRequestPipeline(profile, options.model);
    if (!profile.enabled || profile.enabled.includes('logging')) {
      log = writer(path.resolve(options.logPath || path.join(dataDir, 'native_requests.csv')), LOG_HEADER, !!options.logFsync); opened.push(log);
    }
  } catch (error) { if (engine) engine.native.free(); for (const entry of opened) entry.close(); throw error; }
  const { native, setModel } = engine;
  const maxBytes = profile.max_bytes ?? 65536;
  let closed = false;
  const contextKey = Symbol('aiwaf.native.context');
  const pending = new Set();
  const report = error => { if (options.onError) options.onError(error); else console.error('AIWAF native finalization failed:', error.message); };
  function payload(req) {
    const b = safeBody(req, maxBytes);
    const query = String(req.originalUrl || req.url || '').split('?').slice(1).join('?');
    if (b.exhausted && profile.sql_mode !== 'off') return { status: 413, rule: 'payload_inspection_limit' };
    return JSON.parse(native.inspect_payload(JSON.stringify([query, b.body, req.query ?? null])));
  }
  const middleware = (req, res, next) => {
    if (closed) return next(new Error('Native pipeline is closed'));
    let decision;
    const start = performance.now();
    try {
      const meta = req.aiwafRoute || {};
      const required = new Set((meta.requiredMiddlewares || []).map(normalizeMiddlewareName));
      const disabled = new Set((meta.fullyExempt ? ALL_MIDDLEWARES : meta.exemptMiddlewares || []).map(normalizeMiddlewareName));
      for (const key of required) disabled.delete(key);
      const rawPath = String(req.path || req.url || '/').split('?')[0];
      const body = req[DEFER_BODY] ? {body:null,exhausted:false} : safeBody(req, maxBytes);
      decision = JSON.parse(native.begin(JSON.stringify({
        // Express trust proxy controls forwarded-IP handling. Never trust XFF directly.
        ip: String(req.ip || req.socket?.remoteAddress || 'unknown').replace(/^::ffff:/, ''),
        path: rawPath, method: String(req.method || 'GET'), headers: headers(req.headers),
        query: String(req.originalUrl || req.url || '').split('?').slice(1).join('?'),
        body: body.body, parsed_query: req.query ?? null,
        now: Date.now() / 1000, country: String(synchronous(options.countryLookup, req, '') || ''),
        authenticated: req[DEFER_BODY] ? false : !!synchronous(options.authenticated, req, false),
        exists: !!synchronous(options.routeExists, req, !!req.route), disabled: [...disabled],
        payload_exhausted: body.exhausted, defer_body: !!req[DEFER_BODY]
      })));
    } catch (error) { return next(error); }
    pending.add(decision.context);
    req[contextKey] = decision.context;
    let done = false;
    const finalize = aborted => {
      if (done || closed) return;
      done = true; pending.delete(decision.context);
      try {
        const effects = JSON.parse(native.finish(decision.context, aborted ? 499 : res.statusCode || 200, performance.now() - start, Date.now() / 1000));
        if (blocks && effects.block_csv) blocks.append(effects.block_csv);
        if (keywords && effects.keyword_csv) keywords.append(effects.keyword_csv);
        if (log && effects.log_csv) log.append(effects.log_csv);
      } catch (error) { report(error); }
    };
    res.on('finish', () => finalize(false));
    res.on('close', () => finalize(true));
    if (decision.status) return res.status(decision.status).json({ error: decision.reason });
    return next();
  };
  middleware.inspectPayload = req => {
    const disabled = req.aiwafRoute?.exemptMiddlewares || [];
    if (profile.enabled && !profile.enabled.includes('ip_keyword_block')) return null;
    if (req.aiwafRoute?.fullyExempt || disabled.includes('ip_keyword_block')) return null;
    return payload(req);
  };
  middleware.diagnostics = () => JSON.parse(native.diagnostics());
  middleware.inspectBody = (req, body) => {
    const captured = safeBody({body,headers:{}},maxBytes);
    return JSON.parse(native.inspect_body(req[contextKey], JSON.stringify(captured.body), captured.exhausted,
      !!synchronous(options.authenticated,req,false), Date.now()/1000));
  };
  middleware.setModel = setModel;
  middleware.close = () => {
    if (closed) return;
    if (pending.size) throw new Error('Stop requests and finish in-flight responses before closing the native pipeline');
    closed = true;
    for (const entry of opened) entry.close();
    native.free();
  };
  return middleware;
};
module.exports.DEFER_BODY = DEFER_BODY;
