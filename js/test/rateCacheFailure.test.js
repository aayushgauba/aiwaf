const request = require('supertest');
const express = require('express');
const aiwaf = require('../index');
const blocklist = require('../lib/blocklistManager');
const rateLimiter = require('../lib/rateLimiter');

test('Redis rate cache failure returns generic 503 without calling the application', async () => {
  const unavailable = async () => { throw new Error('redis://secret-password@private-host'); };
  const cache = { lPush: unavailable, expire: unavailable, lLen: unavailable, lRange: unavailable };
  const blocked = jest.spyOn(blocklist, 'isBlocked').mockResolvedValue(false);
  const app = express();
  const handler = jest.fn((_req, res) => res.json({ unexpected: true }));
  app.use(aiwaf({ cache, AIWAF_MIDDLEWARES: ['rate_limit'], AIWAF_MIDDLEWARE_LOGGING: false }));
  app.get('/protected', handler);
  try {
    const response = await request(app).get('/protected').set('X-Forwarded-For', '93.5.7.11');
    expect(response.status).toBe(503);
    expect(JSON.stringify(response.body)).toContain('temporarily_unavailable');
    expect(JSON.stringify(response.body)).not.toMatch(/secret-password|private-host/);
    expect(handler).not.toHaveBeenCalled();
  } finally {
    blocked.mockRestore();
    rateLimiter.cleanup();
  }
});
