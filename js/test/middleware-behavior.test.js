const request = require('supertest');
const express = require('express');
const aiwaf = require('../index');
const db = require('../utils/db');
const blocklistManager = require('../lib/blocklistManager');

describe('AIWAF middleware behavior', () => {
  it('returns text response when JSON errors are disabled and request is non-JSON', async () => {
    const app = express();
    app.use(express.json());
    app.use(aiwaf({
      staticKeywords: ['.php'],
      AIWAF_FORCE_JSON_ERRORS: false,
      WINDOW_SEC: 60,
      MAX_REQ: 1000,
      FLOOD_REQ: 2000
    }));
    app.get('/safe', (req, res) => res.send('ok'));

    const res = await request(app)
      .get('/a.php')
      .set('Accept', 'text/plain')
      .set('X-Forwarded-For', '198.51.120.1')
      .expect(403);

    expect(res.text).toBe('blocked');
    expect(res.headers['content-type']).toMatch(/text\/html|text\/plain/);
  });

  it('enforces geo allowlist mode', async () => {
    const app = express();
    app.use(express.json());
    app.use(aiwaf({
      AIWAF_GEO_BLOCK_ENABLED: true,
      AIWAF_GEO_ALLOW_COUNTRIES: ['US'],
      WINDOW_SEC: 60,
      MAX_REQ: 1000,
      FLOOD_REQ: 2000
    }));
    app.get('/safe', (req, res) => res.send('ok'));

    await request(app)
      .get('/safe')
      .set('x-country-code', 'CA')
      .set('X-Forwarded-For', '198.51.120.2')
      .expect(403);

    await request(app)
      .get('/safe')
      .set('x-country-code', 'US')
      .set('X-Forwarded-For', '198.51.120.3')
      .expect(200, 'ok');
  });

  it('respects allowed path keywords and skips static keyword blocking', async () => {
    const app = express();
    app.use(express.json());
    app.use(aiwaf({
      staticKeywords: ['.php'],
      AIWAF_ALLOWED_PATH_KEYWORDS: ['public'],
      WINDOW_SEC: 60,
      MAX_REQ: 1000,
      FLOOD_REQ: 2000
    }));
    app.get('/public/readme.php', (req, res) => res.send('ok'));

    await request(app)
      .get('/public/readme.php')
      .set('X-Forwarded-For', '198.51.120.4')
      .expect(200, 'ok');
  });

  it('captures redacted extended request information for blocklist decisions', async () => {
    const ip = '198.51.120.40';
    const app = express();
    app.use(aiwaf({
      staticKeywords: ['.php'],
      AIWAF_CAPTURE_EXTENDED_REQUEST_INFO: true,
      AIWAF_WASM_VALIDATION: false
    }));
    await request(app)
      .get('/secret.php')
      .set('X-Forwarded-For', ip)
      .set('Authorization', 'Bearer private')
      .set('User-Agent', 'Mozilla/5.0')
      .expect(403);

    const info = await blocklistManager.getBlockInfo(ip);
    expect(info.extended_request_info.headers.authorization).toBe('[redacted]');
    expect(info.extended_request_info.path).toBe('/secret.php');
    await blocklistManager.unblock(ip);
  });
});

afterAll(async () => {
  await db.destroy();
});
