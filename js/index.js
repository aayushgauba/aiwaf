// aiwaf‑js/index.js
const createExpressMiddleware = require('./lib/wafMiddleware');
const createFastifyPlugin = require('./lib/fastifyPlugin');
const createHapiPlugin = require('./lib/hapiPlugin');
const createKoaMiddleware = require('./lib/koaMiddleware');
const createNestMiddleware = require('./lib/nestMiddleware');
const createNextHandler = require('./lib/nextMiddleware');
const createAdonisMiddleware = require('./lib/adonisMiddleware');
const pathRules = require('./lib/pathRules');
const pathManifest = require('./lib/pathManifest');
const sourceAst = require('./lib/sourceAst');
const wasm = require('./lib/wasmAdapter');
const runtimeUtils = require('./lib/runtimeUtils');
const geoPolicy = require('./lib/geoPolicy');
const trainingLogic = require('./lib/trainingLogic');
const modelSecurity = require('./lib/modelSecurity');
const blockResponses = require('./lib/blockResponses');
const KeywordFallbackStore = require('./lib/keywordFallbackStore');
const whois = require('./lib/whois');
const reputation = require('./lib/reputation');

function withMiddlewares(selection) {
  return (opts = {}) => createExpressMiddleware({
    ...opts,
    AIWAF_MIDDLEWARES: opts.AIWAF_MIDDLEWARES || opts.middlewares || [selection]
  });
}

module.exports = createExpressMiddleware;
// Await startup once; this path requires native support and has no JS policy fallback.
module.exports.native = require('./lib/nativePipeline');
module.exports.fastify = createFastifyPlugin;
module.exports.hapi = createHapiPlugin;
module.exports.koa = createKoaMiddleware;
module.exports.nest = createNestMiddleware;
module.exports.next = createNextHandler;
module.exports.adonis = createAdonisMiddleware;
module.exports.bodyParser = require('./lib/bodyParser');
module.exports.sails = createExpressMiddleware;
module.exports.auto = withMiddlewares('auto');
module.exports.all = withMiddlewares('all');
module.exports.exempt = pathRules.exempt;
module.exports.exemptFrom = pathRules.exemptFrom;
module.exports.only = pathRules.only;
module.exports.requireProtection = pathRules.requireProtection;
module.exports.shouldApplyMiddleware = (path, middlewareName, rules = []) =>
  pathRules.createRoutePlan(path, rules).shouldApply(middlewareName);
module.exports.getPathRuleOverrides = pathRules.getPathRuleOverrides;
module.exports.pathManifest = pathManifest;
module.exports.sourceAst = sourceAst;
module.exports.wasm = wasm;
module.exports.runtimeUtils = runtimeUtils;
module.exports.geoPolicy = geoPolicy;
module.exports.trainingLogic = trainingLogic;
module.exports.modelSecurity = modelSecurity;
module.exports.blockResponses = blockResponses;
module.exports.KeywordFallbackStore = KeywordFallbackStore;
module.exports.whois = whois;
module.exports.reputation = reputation;
module.exports.extractExpressRoutes = pathManifest.extractExpressRoutes;
module.exports.extractFastifyRoutes = pathManifest.extractFastifyRoutes;
module.exports.extractHapiRoutes = pathManifest.extractHapiRoutes;
module.exports.extractKoaRoutes = pathManifest.extractKoaRoutes;
module.exports.extractNextRoutes = pathManifest.extractNextRoutes;
module.exports.extractNestRoutes = pathManifest.extractNestRoutes;
module.exports.generateExpressManifest = pathManifest.generateExpressManifest;
module.exports.generateFrameworkManifest = pathManifest.generateFrameworkManifest;
