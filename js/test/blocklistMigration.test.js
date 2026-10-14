process.env.NODE_ENV = 'test';

describe('blocklist schema migration', () => {
  test('upgrades a legacy SQLite table without losing existing blocks', async () => {
    jest.resetModules();
    jest.dontMock('../utils/db');
    const db = require('../utils/db');
    await db.schema.createTable('blocked_ips', table => {
      table.increments('id').primary();
      table.string('ip_address').unique().notNullable();
      table.string('reason');
      table.timestamp('blocked_at');
    });
    await db('blocked_ips').insert({
      ip_address: '203.0.113.70', reason: 'legacy scanner', blocked_at: new Date().toISOString()
    });

    const manager = require('../lib/blocklistManager');
    await expect(manager.initialize()).resolves.toBe(true);
    expect(await db.schema.hasColumn('blocked_ips', 'reputation_reason')).toBe(true);
    expect(await db.schema.hasColumn('blocked_ips', 'extended_request_info')).toBe(true);
    expect(await manager.isBlocked('203.0.113.70')).toBe(true);
    const result = await manager.migrateLegacy();
    expect(result).toEqual({ total: 1, changed: 1 });
    expect((await manager.getBlockInfo('203.0.113.70')).permanent).toBe(true);
    await db.destroy();
  });
});
