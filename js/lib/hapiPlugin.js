const createExpressMiddleware = require('./wafMiddleware');
const { version } = require('../package.json');

function createExpressLikeResponse(h, rawRes) {
  const res = {
    locals: {},
    on: (...args) => rawRes.on(...args),
    get statusCode() {
      return rawRes.statusCode;
    },
    set statusCode(code) {
      rawRes.statusCode = code;
    },
    status(code) {
      res.statusCode = code;
      res._statusCode = code;
      res._handled = true;
      return res;
    },
    json(payload) {
      res._payload = payload;
      res._contentType = 'application/json';
      res._handled = true;
      return res;
    },
    send(payload) {
      res._payload = payload;
      res._handled = true;
      return res;
    }
  };

  res.toResponse = () => {
    const response = h.response(res._payload);
    if (res._contentType) {
      response.type(res._contentType);
    }
    if (res._statusCode) {
      response.code(res._statusCode);
    }
    return response;
  };

  return res;
}

module.exports = {
  name: 'aiwaf',
  version,
  register: async (server, opts = {}) => {
    const middleware = createExpressMiddleware(opts);

    if (middleware.ready) {
      const native = await middleware.ready;
      const { DEFER_BODY } = require('./nativePipeline');
      server.ext('onRequest', (request, h) => {
        const req = request.raw.req;
        req.ip = request.info.remoteAddress; req.path = request.path;
        req.url = request.url.pathname + request.url.search;
        req[DEFER_BODY] = true;
        req.body = undefined; req.query = undefined;
        const res = createExpressLikeResponse(h, request.raw.res);
        native(req, res, error => { if (error) throw error; });
        return res._handled ? res.toResponse().takeover() : h.continue;
      });
      server.ext('onPreHandler', (request,h) => {
        request.raw.req.auth = request.auth;
        const finding=native.inspectBody(request.raw.req,request.payload);
        return finding ? h.response({error:finding.rule}).code(finding.status).takeover() : h.continue;
      });
      server.events.once('stop', () => native.close());
      return;
    }

    server.ext('onPreHandler', async (request, h) => {
      const finding = await middleware.inspectPayload({
        headers: request.headers, ip: request.info?.remoteAddress,
        path: request.path, url: request.url?.href,
        body: request.payload, query: request.query, aiwafRoute: request.raw.req.aiwafRoute
      });
      return finding ? h.response({ error: finding.rule }).code(finding.status).takeover() : h.continue;
    });

    server.ext('onRequest', async (request, h) => {
      const res = createExpressLikeResponse(h, request.raw.res);
      const req = request.raw.req;
      
      // Set path and URL from Hapi's request object
      req.path = request.path || req.path;
      req.url = request.url?.pathname || req.url;
      
      // For headers: prefer the framework's parsed headers, but merge them
      // Don't try to replace req.headers entirely as it's read-only on raw requests
      if (request.headers) {
        // Copy headers to the req.headers object (which is read-only but properties can be added)
        try {
          Object.keys(request.headers).forEach(key => {
            if (!req.headers[key]) {
              req.headers[key] = request.headers[key];
            }
          });
        } catch (err) {
          // If we can't modify headers, continue anyway
        }
      }
      
      req.ip = request.info?.remoteAddress || req.ip;

      return new Promise(resolve => {
        let resolved = false;
        const finish = () => {
          if (resolved) return;
          resolved = true;
          if (res._payload !== undefined || res._statusCode) {
            resolve(res.toResponse().takeover());
          } else {
            resolve(h.continue);
          }
        };
        const maybePromise = middleware(req, res, finish);
        Promise.resolve(maybePromise).then(finish).catch(finish);
      });
    });
  }
};
