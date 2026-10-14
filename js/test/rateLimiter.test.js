const blocklistManager = require('../lib/blocklistManager');
const rateLimiter = require('../lib/rateLimiter');

describe('rateLimiter', () => {
  afterEach(() => rateLimiter.cleanup());

  test('unavailable external cache fails closed by default without leaking backend details', async () => {
    const cache = Object.fromEntries(['lPush', 'expire', 'lLen', 'lRange'].map(name =>
      [name, jest.fn().mockRejectedValue(new Error('redis://secret-password@private-host'))]));
    const blocklist = jest.spyOn(blocklistManager, 'isBlocked').mockResolvedValue(false);
    await rateLimiter.init({ cache });
    await expect(rateLimiter.record('93.1.2.3')).rejects.toMatchObject({ code: 'AIWAF_RATE_CACHE_UNAVAILABLE', message: 'Rate cache unavailable' });
    await expect(rateLimiter.isBlocked('93.1.2.3')).rejects.toMatchObject({ code: 'AIWAF_RATE_CACHE_UNAVAILABLE' });
    await rateLimiter.init({ cache, AIWAF_RATE_CACHE_FAILURE_MODE: 'open' });
    await expect(rateLimiter.record('93.1.2.3')).resolves.toBeUndefined();
    await expect(rateLimiter.isBlocked('93.1.2.3')).resolves.toBe(false);
    blocklist.mockRestore();
  });

  test('uses fallback cache operations and performs cleanup', async () => {
    jest.spyOn(blocklistManager, 'isBlocked').mockResolvedValue(false);
    await rateLimiter.init({ WINDOW_SEC: 1, MAX_REQ: 1, FLOOD_REQ: 20 });
    await rateLimiter.record('203.0.113.9');
    expect(await rateLimiter.isBlocked('203.0.113.9')).toBe(false);
    await rateLimiter.record('203.0.113.9');
    expect(await rateLimiter.isBlocked('203.0.113.9')).toBe(true);

    rateLimiter.cleanupExpired();
    const now = Date.now();
    jest.spyOn(Date, 'now').mockReturnValue(now + 3000);
    rateLimiter.cleanupExpired();
    expect(await rateLimiter.isBlocked('203.0.113.9')).toBe(false);
    Date.now.mockRestore();

    rateLimiter.cleanup();
    blocklistManager.isBlocked.mockRestore();
  });
});
