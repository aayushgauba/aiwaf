const Hapi = require('@hapi/hapi');
const aiwaf = require('../index');

process.env.NODE_ENV = 'test';

const testCache = (() => {
  const store = new Map();
  return {
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async set(key, val) {
      store.set(key, val);
    }
  };
})();

async function buildServer(opts = {}) {
  const server = Hapi.server({ port: 0 });
  await server.register({
    plugin: aiwaf.hapi,
    options: {
      cache: testCache,
      WINDOW_SEC: 60,
      MAX_REQ: 1000,
      FLOOD_REQ: 2000,
      ...opts
    }
  });

  server.route({ method: 'GET', path: '/safe', handler: () => 'ok' });
  server.route({ method: 'POST', path: '/safe', handler: () => 'ok' });
  return server;
}

describe('AIWAF Hapi plugin', () => {
  it('blocks SQL login payloads after Hapi parses the body', async () => {
    const server = await buildServer({ AIWAF_WASM_VALIDATION: false, AIWAF_MIDDLEWARES: ['ip_keyword_block'] });
    const result = await server.inject({ method: 'POST', url: '/safe',
      headers: { 'x-forwarded-for': '93.184.217.11' }, payload: { email: "admin'--", password: 'x' } });
    expect(result.statusCode).toBe(403);
    expect(result.result.error).toBe('sql_quote_comment');
    await server.stop();
  });
  it('implements the response send contract', async () => {
    jest.resetModules();
    jest.doMock('../lib/wafMiddleware', () => () => (_req, res) => res.send('adapter-send'));
    const plugin = require('../lib/hapiPlugin');
    let extension;
    await plugin.register({ ext: (_name, fn) => { extension = fn; } });
    const response = { takeover: jest.fn(() => 'taken') };
    const h = { response: jest.fn(() => response), continue: Symbol('continue') };
    const request = {
      raw: { req: { headers: {} }, res: { on: jest.fn(), statusCode: 200 } },
      headers: {}, path: '/', url: { pathname: '/' }, info: { remoteAddress: '203.0.113.1' }
    };
    await expect(extension(request, h)).resolves.toBe('taken');
    expect(h.response).toHaveBeenCalledWith('adapter-send');
    jest.dontMock('../lib/wafMiddleware');
  });

  it('allows safe requests', async () => {
    const server = await buildServer();
    const res = await server.inject({
      method: 'GET',
      url: '/safe',
      headers: { 'x-forwarded-for': '198.51.100.20',
        'user-agent': 'Mozilla/5.0 Chrome/130.0 Safari/537.36',
        accept: 'text/html', 'accept-language': 'en', 'accept-encoding': 'gzip' }
    });
    expect(res.statusCode).toBe(200);
    await server.stop();
  });

  it('blocks static keyword paths', async () => {
    const server = await buildServer({ staticKeywords: ['.php'] });
    const res = await server.inject({
      method: 'GET',
      url: '/wp-config.php',
      headers: { 'x-forwarded-for': '198.51.100.21' }
    });
    expect(res.statusCode).toBe(403);
    const payload = JSON.parse(res.payload);
    expect(payload).toEqual({ error: 'blocked' });
    await server.stop();
  });

  it('enforces method policy when enabled', async () => {
    const server = await buildServer({
      AIWAF_METHOD_POLICY_ENABLED: true,
      AIWAF_ALLOWED_METHODS: ['GET']
    });
    const res = await server.inject({
      method: 'POST',
      url: '/safe',
      headers: { 'x-forwarded-for': '198.51.100.22' }
    });
    expect(res.statusCode).toBe(405);
    const payload = JSON.parse(res.payload);
    expect(payload).toEqual({ error: 'blocked' });
    await server.stop();
  });

  it('enforces header validation requirements', async () => {
    const server = await buildServer({
      AIWAF_HEADER_VALIDATION: true,
      AIWAF_REQUIRED_HEADERS: ['x-required-security-header']
    });
    const res = await server.inject({
      method: 'GET',
      url: '/safe',
      headers: {
        'x-forwarded-for': '198.51.100.23',
        accept: 'application/json'
      }
    });
    expect(res.statusCode).toBe(403);
    const payload = JSON.parse(res.payload);
    expect(payload).toEqual({ error: 'blocked' });
    await server.stop();
  });

  it('rate limits repeated requests', async () => {
    const server = await buildServer({
      WINDOW_SEC: 60,
      MAX_REQ: 1,
      FLOOD_REQ: 2
    });
    const headers = {
      'x-forwarded-for': '198.51.100.24',
      'user-agent': 'Mozilla/5.0 Chrome/130.0 Safari/537.36',
      'accept-language': 'en', 'accept-encoding': 'gzip',
      accept: 'application/json'
    };
    const first = await server.inject({ method: 'GET', url: '/safe', headers });
    expect(first.statusCode).toBe(200);

    const second = await server.inject({ method: 'GET', url: '/safe', headers });
    expect(second.statusCode).toBe(429);
    const payload = JSON.parse(second.payload);
    expect(payload).toEqual({ error: 'too_many_requests' });
    await server.stop();
  });
});
