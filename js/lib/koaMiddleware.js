const createExpressMiddleware = require('./wafMiddleware');

function createExpressLikeResponse(ctx) {
  const res = {
    locals: {},
    on: (...args) => ctx.res.on(...args),
    get statusCode() {
      return ctx.status;
    },
    set statusCode(code) {
      ctx.status = code;
    },
    status(code) {
      res.statusCode = code;
      res._handled = true;
      return res;
    },
    json(payload) {
      ctx.type = 'application/json';
      ctx.body = payload;
      res._handled = true;
      return res;
    },
    send(payload) {
      ctx.body = payload;
      res._handled = true;
      return res;
    }
  };
  return res;
}

module.exports = function createKoaMiddleware(opts = {}) {
  const middleware = createExpressMiddleware(opts);

  const wrapper = async (ctx, next) => {
    const res = createExpressLikeResponse(ctx);
    const req = ctx.req;  // Raw Node.js http.IncomingMessage - already has headers
    
    // Only set these if not already available
    if (!req.path) req.path = ctx.path;
    if (!req.url) req.url = ctx.url;
    if (!req.ip) req.ip = ctx.ip;
    if (req.body === undefined) req.body = ctx.request?.body;
    if (req.query === undefined) req.query = ctx.query;
    
    // Don't override headers - use what's already on the raw request
    // ctx.headers is Koa's parsed version, but req.headers from Node.js has the originals

    await new Promise((resolve, reject) => {
      let resolved = false;
      const finish = error => {
        if (resolved) return;
        resolved = true;
        if (error) { reject(error); return; }
        resolve();
      };
      const maybePromise = middleware(req, res, finish);
      if (res._handled) {
        finish();
      }
      Promise.resolve(maybePromise).then(() => finish()).catch(reject);
    });

    if (ctx.body !== undefined) {
      return;
    }

    await next();
  };
  if (middleware.ready) wrapper.ready = middleware.ready;
  return wrapper;
};
