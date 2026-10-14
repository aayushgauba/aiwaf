describe('blacklistManager', () => {
  beforeEach(() => jest.resetModules());

  test('exposes an idempotent initialize operation', async () => {
    const db = jest.fn();
    db.schema = { hasTable: jest.fn(async () => true) };
    db.fn = { now: jest.fn() };
    jest.doMock('../utils/db', () => db);
    const manager = require('../lib/blacklistManager');
    await expect(manager.initialize()).resolves.toBe(true);
    await expect(manager.initialize()).resolves.toBe(true);
    expect(db.schema.hasTable).toHaveBeenCalledTimes(1);
  });

  test('stores reputation, temporary expiry, statistics, and permanent blocks in CSV fallback', async () => {
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aiwaf-blacklist-'));
    process.env.AIWAF_BLOCKED_IPS_CSV_PATH = path.join(dir, 'blocked.csv');
    process.env.AIWAF_IP_EXEMPTIONS_CSV_PATH = path.join(dir, 'ip-exemptions.csv');
    process.env.AIWAF_PATH_EXEMPTIONS_CSV_PATH = path.join(dir, 'path-exemptions.csv');
    jest.doMock('../utils/db', () => {
      const failingDb = jest.fn();
      failingDb.schema = { hasTable: jest.fn(async () => { throw new Error('offline'); }) };
      failingDb.fn = { now: jest.fn() };
      return failingDb;
    });
    const manager = require('../lib/blacklistManager');

    await manager.block('203.0.113.10', 'scanner', { now: 100 });
    await manager.block('203.0.113.10', 'SQL injection', { now: 200, extendedRequestInfo: { path: '/x' } });
    const info = await manager.getBlockInfo('203.0.113.10');
    expect(info).toEqual(expect.objectContaining({ score: 60, offenses: 2, duration: 3600 }));
    expect(info.extended_request_info).toEqual({ path: '/x' });
    expect(await manager.isBlocked('203.0.113.10')).toBe(false);
    expect(await manager.getBlockInfo('203.0.113.10')).not.toBeNull();
    expect(await manager.cleanupExpired()).toBe(1);

    await manager.blockPermanent('203.0.113.11', 'manual');
    expect(await manager.isBlocked('203.0.113.11')).toBe(true);
    expect(await manager.getStatistics()).toEqual(expect.objectContaining({ total: 1, active: 1, permanent: 1 }));
    expect(await manager.getRecentBlocks(24)).toHaveLength(1);
    expect(await manager.getTopBlockedReasons()).toEqual([{ reason: 'manual', count: 1 }]);
    expect(await manager.bulkBlock(['203.0.113.12'], 'flood')).toEqual({ '203.0.113.12': true });
    expect(await manager.bulkUnblock(['203.0.113.12'])).toEqual({ '203.0.113.12': true });
    await manager.blockTemporary('203.0.113.15', 'temporary', 2);
    expect((await manager.getBlockInfo('203.0.113.15')).duration).toBe(120);
    await manager.unblock('203.0.113.15');
    expect(await manager.importRecords([{ ip_address: '203.0.113.13', reason: 'legacy' }])).toBe(1);
    expect(await manager.migrateLegacy({ duration: 3600, now: 1000 })).toEqual(expect.objectContaining({ changed: 1 }));
    expect(await manager.exportRecords()).toHaveLength(2);
    await manager.block('203.0.113.14', 'temporary', { duration: 1, now: 1 });
    expect(await manager.cleanupExpired(10)).toBe(1);
    await manager.addToWhitelist('203.0.113.20', 'trusted');
    expect(await manager.isWhitelisted('203.0.113.20')).toBe(true);
    expect((await manager.getWhitelist()).ips).toHaveLength(1);
    expect(await manager.block('203.0.113.20', 'scanner')).toBe(false);
    expect(await manager.removeFromWhitelist('203.0.113.20')).toBe(1);
    delete process.env.AIWAF_BLOCKED_IPS_CSV_PATH;
    delete process.env.AIWAF_IP_EXEMPTIONS_CSV_PATH;
    delete process.env.AIWAF_PATH_EXEMPTIONS_CSV_PATH;
  });
});
