const createExpressMiddleware = require('./wafMiddleware');

function createExpressLikeResponse(reply) {
  const raw = reply.raw;
  const res = {
    locals: {},
    on: (...args) => raw.on(...args),
    get statusCode() {
      return raw.statusCode;
    },
    set statusCode(code) {
      raw.statusCode = code;
    },
    status(code) {
      res.statusCode = code;
      reply.code(code);
      return res;
    },
    json(payload) {
      reply.type('application/json').send(payload);
      return res;
    },
    send(payload) {
      reply.send(payload);
      return res;
    }
  };
  return res;
}

function fastifyPlugin(fastify, opts = {}, done) {
  const middleware = createExpressMiddleware(opts);

  if (middleware.ready) {
    // Parsed bodies are available here; do not reject/inspect an unparsed stream onRequest.
    fastify.addHook('preValidation', async (request, reply) => {
      const native = await middleware.ready;
      const req = request.raw;
      req.ip = request.ip; req.body = request.body; req.query = request.query;
      req.path = String(req.url || '/').split('?')[0];
      await native(req, createExpressLikeResponse(reply), error => { if (error) throw error; });
      if (reply.sent) return reply;
    });
    fastify.addHook('onClose', async () => (await middleware.ready).close());
    middleware.ready.then(() => done(), done);
    return;
  }

  fastify.addHook('onRequest', async (request, reply) => {
    const res = createExpressLikeResponse(reply);
    await middleware(request.raw, res, () => {});

    if (reply.sent) {
      return reply;
    }
  });

  fastify.addHook('preValidation', async (request, reply) => {
    const finding = await middleware.inspectPayload({
      headers: request.headers, ip: request.ip, url: request.raw.url,
      body: request.body, query: request.query, aiwafRoute: request.raw.aiwafRoute
    });
    if (finding) return reply.code(finding.status).send({ error: finding.rule });
  });

  done();
}

fastifyPlugin[Symbol.for('skip-override')] = true;

module.exports = fastifyPlugin;
