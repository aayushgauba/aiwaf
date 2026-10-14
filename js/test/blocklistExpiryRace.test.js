const fs = require('fs');
const os = require('os');
const path = require('path');

describe('blocklist expiry concurrency', () => {
  let dir;
  beforeEach(() => {
    jest.resetModules();
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aiwaf-expiry-'));
    process.env.AIWAF_BLOCKED_IPS_CSV_PATH = path.join(dir, 'blocked.csv');
    jest.doMock('../utils/db', () => ({ schema: {
      hasTable: async () => { throw new Error('Force CSV'); }
    } }));
  });
  afterEach(() => {
    delete process.env.AIWAF_BLOCKED_IPS_CSV_PATH;
    jest.restoreAllMocks();
    if (path.dirname(dir) !== os.tmpdir() || !path.basename(dir).startsWith('aiwaf-expiry-')) {
      throw new Error('Unexpected test directory');
    }
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('expired request snapshot cannot erase a concurrent refresh', async () => {
    const manager = require('../lib/blocklistManager');
    const csv = require('../lib/csvStore');
    await manager.block('203.0.113.9', 'expired', { now: 1, duration: 1, checkExemptions: false });
    const original = fs.readFileSync;
    jest.spyOn(fs, 'readFileSync').mockImplementation((file, ...args) => {
      const old = original(file, ...args);
      if (file === process.env.AIWAF_BLOCKED_IPS_CSV_PATH) {
        fs.readFileSync.mockRestore();
        const headers = old.trim().split('\n')[0].split(',');
        const rows = csv.readRows(file, headers);
        rows[0].expires_at = Date.now() / 1000 + 900;
        csv.writeRows(file, headers, rows);
      }
      return old;
    });
    expect(await manager.isBlocked('203.0.113.9')).toBe(false);
    expect(await manager.isBlocked('203.0.113.9')).toBe(true);
  });

  test('cleanup waits for a writer and checks its latest expiry', async () => {
    const manager = require('../lib/blocklistManager');
    const csv = require('../lib/csvStore');
    const file = process.env.AIWAF_BLOCKED_IPS_CSV_PATH;
    await manager.block('203.0.113.9', 'expired', { now: 1, duration: 1, checkExemptions: false });
    fs.mkdirSync(`${file}.lock`);
    const cleaning = manager.cleanupExpired();
    await new Promise(resolve => setTimeout(resolve, 50));
    const headers = fs.readFileSync(file, 'utf8').trim().split('\n')[0].split(',');
    const rows = csv.readRows(file, headers);
    rows[0].expires_at = Date.now() / 1000 + 900;
    csv.writeRows(file, headers, rows);
    fs.rmdirSync(`${file}.lock`);
    expect(await cleaning).toBe(0);
    expect(await manager.isBlocked('203.0.113.9')).toBe(true);
  });

  test('database deletion rechecks expiry after a concurrent refresh', async () => {
    const knex = require('knex')({ client: 'sqlite3', connection: { filename: ':memory:' }, useNullAsDefault: true });
    let refresh = false;
    const db = table => {
      const query = knex(table);
      const remove = query.del.bind(query);
      query.del = async () => {
        if (refresh) {
          refresh = false;
          await knex(table).where('ip_address', '203.0.113.9').update({ expires_at: Date.now() / 1000 + 900 });
        }
        return remove();
      };
      return query;
    };
    db.schema = knex.schema;
    db.fn = knex.fn;
    jest.doMock('../utils/db', () => db);
    const manager = require('../lib/blocklistManager');
    try {
      await manager.block('203.0.113.9', 'expired', { now: 1, duration: 1, checkExemptions: false });
      refresh = true;
      expect(await manager.cleanupExpired()).toBe(0);
      expect(await manager.isBlocked('203.0.113.9')).toBe(true);
      await manager.block('203.0.113.10', 'expired', { now: 1, duration: 1, checkExemptions: false });
      await knex('blocked_ips').insert({ ip_address: '203.0.113.11', reason: 'legacy', expires_at: 2, permanent: false });
      expect(await manager.cleanupExpired()).toBe(1);
      expect(await manager.isBlocked('203.0.113.11')).toBe(true);
    } finally { await knex.destroy(); }
  });
});
