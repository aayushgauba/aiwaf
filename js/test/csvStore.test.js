const fs = require('fs');
const path = require('path');

function makeFailingDbMock() {
  const db = function dbCall() {
    return {
      where() {
        return {
          first: async () => { throw new Error('db down'); },
          del: async () => { throw new Error('db down'); }
        };
      },
      insert: async () => { throw new Error('db down'); },
      onConflict() {
        return {
          ignore: async () => { throw new Error('db down'); }
        };
      },
      select() {
        return {
          orderBy: async () => { throw new Error('db down'); },
          limit: async () => { throw new Error('db down'); }
        };
      }
    };
  };

  db.schema = {
    hasTable: async () => { throw new Error('db down'); },
    createTable: async () => { throw new Error('db down'); }
  };
  db.fn = { now: () => new Date() };
  db.raw = () => '0';
  return db;
}

function setupCsvPaths(prefix) {
  const baseDir = path.join(process.cwd(), 'logs', 'test-csv-fallback', prefix);
  fs.mkdirSync(baseDir, { recursive: true });

  process.env.AIWAF_BLOCKED_IPS_CSV_PATH = path.join(baseDir, 'blocked_ips.csv');
  process.env.AIWAF_IP_EXEMPTIONS_CSV_PATH = path.join(baseDir, 'ip_exemptions.csv');
  process.env.AIWAF_PATH_EXEMPTIONS_CSV_PATH = path.join(baseDir, 'path_exemptions.csv');
  process.env.AIWAF_GEO_BLOCKED_COUNTRIES_CSV_PATH = path.join(baseDir, 'geo_blocked_countries.csv');
  process.env.AIWAF_REQUEST_LOGS_CSV_PATH = path.join(baseDir, 'request_logs.csv');

  return baseDir;
}

describe('CSV fallback stores', () => {
  let baseDir;

  beforeEach(() => {
    jest.resetModules();
    baseDir = setupCsvPaths(`run-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    jest.doMock('../utils/db', () => makeFailingDbMock());
  });

  afterEach(() => {
    try {
      fs.rmSync(baseDir, { recursive: true, force: true });
    } catch (err) {
      // noop
    }
  });

  it('blocklistManager falls back to CSV for block/list/unblock/clear', async () => {
    const blocklistManager = require('../lib/blocklistManager');

    await blocklistManager.block('203.0.113.10', 'test');
    await blocklistManager.block('203.0.113.11', 'test2');

    expect(await blocklistManager.isBlocked('203.0.113.10')).toBe(true);

    const rows = await blocklistManager.getBlockedIPs();
    expect(rows.length).toBe(2);

    const removed = await blocklistManager.unblock('203.0.113.10');
    expect(removed).toBe(true);
    expect(await blocklistManager.isBlocked('203.0.113.10')).toBe(false);

    const cleared = await blocklistManager.clear();
    expect(cleared).toBe(1);
    expect((await blocklistManager.getBlockedIPs()).length).toBe(0);
  });

  it('exemptionStore falls back to CSV for IP and path exemptions', async () => {
    const exemptionStore = require('../lib/exemptionStore');

    await exemptionStore.addIp('198.51.100.40', 'ops');
    await exemptionStore.addPath('/health', 'probe');

    expect(await exemptionStore.isIpExempt('198.51.100.40')).toBe(true);
    expect(await exemptionStore.isPathExempt('/health/live')).toBe(true);

    const ips = await exemptionStore.listIps();
    const paths = await exemptionStore.listPaths();
    expect(ips.length).toBe(1);
    expect(paths.length).toBe(1);

    expect(await exemptionStore.removeIp('198.51.100.40')).toBe(1);
    expect(await exemptionStore.removePath('/health')).toBe(1);
    expect(await exemptionStore.isIpExempt('198.51.100.40')).toBe(false);
    expect(await exemptionStore.isPathExempt('/health/live')).toBe(false);
  });

  it('geoStore falls back to CSV for country block operations', async () => {
    const geoStore = require('../lib/geoStore');

    await geoStore.addBlockedCountry('CN', 'manual');
    await geoStore.addBlockedCountry('RU', 'manual');

    expect(await geoStore.isBlockedCountry('CN')).toBe(true);

    const rows = await geoStore.listBlockedCountries();
    expect(rows.map(r => r.country_code)).toEqual(['CN', 'RU']);

    const removed = await geoStore.removeBlockedCountry('CN');
    expect(removed).toBe(1);
    expect(await geoStore.isBlockedCountry('CN')).toBe(false);
  });

  it('requestLogStore falls back to CSV for insert/recent/summary/clear', async () => {
    const requestLogStore = require('../lib/requestLogStore');

    await requestLogStore.insert({
      timestamp: new Date().toISOString(),
      ip: '192.0.2.10',
      method: 'GET',
      path: '/geo-a',
      status: 403,
      responseTime: 20,
      blocked: true,
      reason: 'geo_block:CN',
      country: 'CN',
      userAgent: 'jest'
    });

    await requestLogStore.insert({
      timestamp: new Date().toISOString(),
      ip: '192.0.2.11',
      method: 'GET',
      path: '/geo-b',
      status: 200,
      responseTime: 12,
      blocked: false,
      reason: '',
      country: 'US',
      userAgent: 'jest'
    });

    const recent = await requestLogStore.recent(10);
    expect(recent.length).toBe(2);

    const summary = await requestLogStore.geoSummary(10);
    const cn = summary.find(row => row.country === 'CN');
    expect(cn).toBeDefined();
    expect(cn.requests).toBe(1);
    expect(cn.blocked_count).toBe(1);

    const cleared = await requestLogStore.clear();
    expect(cleared).toBe(2);
    expect((await requestLogStore.recent(10)).length).toBe(0);
  });
});
