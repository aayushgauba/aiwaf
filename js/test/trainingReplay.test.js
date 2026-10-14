const fs = require('fs');
const os = require('os');
const path = require('path');

describe('trainer enforcement with real WASM receipts and CSV blocks', () => {
  let directory, originalEnvironment;
  beforeEach(() => {
    jest.resetModules();
    originalEnvironment = { ...process.env };
    directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aiwaf-replay-'));
    Object.assign(process.env, {
      AIWAF_TRAINING_STATE_DIR: directory,
      AIWAF_BLOCKED_IPS_CSV_PATH: path.join(directory, 'blocked.csv'),
      AIWAF_ACCESS_LOG: path.join(directory, 'access.log'), NODE_LOG_GLOB: path.join(directory, '*.rotated'),
      AIWAF_MIDDLEWARE_LOG_PATH: path.join(directory, 'missing.jsonl'),
      AIWAF_MIDDLEWARE_LOG_CSV_PATH: path.join(directory, 'missing.csv'),
      AIWAF_MIN_TRAIN_LOGS: '1', AIWAF_MIN_AI_LOGS: '10000', AIWAF_ENABLE_KEYWORD_LEARNING: 'false',
      AIWAF_FORCE_AI_TRAINING: 'false'
    });
    if (process.env.AIWAF_NATIVE_TEST_MODULE) {
      jest.doMock(require.resolve('aiwaf-wasm'), () => require(process.env.AIWAF_NATIVE_TEST_MODULE));
    }
    jest.doMock('../utils/db', () => {
      const db = () => { throw new Error('test CSV backend'); };
      db.schema = { hasTable: async () => { throw new Error('test CSV backend'); } };
      return db;
    });
    jest.doMock('../lib/exemptionStore', () => ({ initialize: async () => {}, listPaths: async () => [],
      listIps: async () => [], isIpExempt: async () => false }));
    jest.doMock('../lib/requestLogStore', () => ({ recent: async () => [] }));
    jest.doMock('../lib/modelStore', () => ({ save: async () => {} }));
    jest.doMock('../lib/dynamicKeywordStore', () => ({ add: async () => {}, remove: async () => {} }));
  });
  afterEach(() => {
    jest.restoreAllMocks();
    process.env = originalEnvironment;
    if (path.dirname(directory) !== path.resolve(os.tmpdir())
        || !path.basename(directory).startsWith('aiwaf-replay-')) throw new Error('Unsafe test cleanup');
    fs.rmSync(directory, { recursive: true, force: true });
  });

  function write(count, status = 404, target = '/missing.php') {
    fs.writeFileSync(path.join(directory, 'access.log'), Array.from({ length: count }, (_, i) =>
      `203.0.113.1 - - [10/Oct/2026:12:00:${String(i).padStart(2, '0')} +0000] "GET ${target} HTTP/1.1" ${status} 123 "-" "-" response-time=0.1`
    ).join('\n') + '\n');
  }
  async function run() {
    let train;
    jest.isolateModules(() => { train = require('../train'); });
    await train();
  }

  test.each(['manual', 'expiry'])('%s removal cannot be undone by replay; fresh 404s accumulate', async removal => {
    write(6);
    await run();
    const manager = require('../lib/blacklistManager');
    const before = await manager.getBlockedIPs();
    expect(before).toHaveLength(1);
    await run();
    expect(await manager.getBlockedIPs()).toEqual(before);
    if (removal === 'manual') await manager.unblock('203.0.113.1');
    else {
      jest.spyOn(Date, 'now').mockReturnValue((before[0].expires_at + 1) * 1000);
      expect(await manager.isBlocked('203.0.113.1')).toBe(false);
    }
    await run();
    expect(await manager.isBlocked('203.0.113.1')).toBe(false);
    write(11);
    await run();
    expect(await manager.isBlocked('203.0.113.1')).toBe(false);
    write(12);
    await run();
    expect(await manager.isBlocked('203.0.113.1')).toBe(true);
  });

  test('AI fitting keeps history while enforcement scores only new benign traffic', async () => {
    process.env.AIWAF_FORCE_AI_TRAINING = 'true';
    const fitted = [], scored = [];
    jest.doMock('../lib/wasmAdapter', () => ({ ...jest.requireActual('../lib/wasmAdapter'),
      createIsolationForest: async () => ({ fit: values => fitted.push(values.length), toJSON: () => ({}),
        isAnomaly: features => { scored.push(features); return true; } }) }));
    write(6, 500, '/wp-admin/shell.php');
    await run();
    const manager = require('../lib/blacklistManager');
    expect(await manager.isBlocked('203.0.113.1')).toBe(true);
    await manager.unblock('203.0.113.1');
    scored.length = 0;
    fs.appendFileSync(path.join(directory, 'access.log'),
      '203.0.113.1 - - [10/Oct/2026:12:01:00 +0000] "GET /docs HTTP/1.1" 200 123 "-" "-" response-time=0.1\n');
    await run();
    expect(fitted).toEqual([6, 7]);
    expect(scored).toHaveLength(1);
    expect(scored[0][1]).toBe(0);
    expect(await manager.isBlocked('203.0.113.1')).toBe(false);
  });

  test('CLI reports corrupted receipt state as a failure', async () => {
    fs.writeFileSync(path.join(directory, 'node_training_evidence.json'), '{broken');
    const previousCode = process.exitCode;
    const report = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      await require('../train').runCLI();
      expect(process.exitCode).toBe(1);
      expect(report).toHaveBeenCalled();
    } finally { process.exitCode = previousCode; }
  });

  test.each(['JSONL', 'CSV', 'database'])('%s history cannot replay enforcement after removal', async source => {
    const events = Array.from({ length: 6 }, (_, i) => ({ ip: '203.0.113.1', path: '/missing.php',
      status: 404, timestamp: new Date(Date.UTC(2026, 9, 10, 0, 0, i)).toISOString() }));
    if (source === 'JSONL') {
      fs.writeFileSync(process.env.AIWAF_MIDDLEWARE_LOG_PATH, events.map(row => JSON.stringify(row)).join('\n'));
    } else if (source === 'CSV') {
      fs.writeFileSync(process.env.AIWAF_MIDDLEWARE_LOG_CSV_PATH, 'timestamp,ip,method,path,status,responseTime\n'
        + events.map(row => `${row.timestamp},${row.ip},GET,${row.path},404,10`).join('\n'));
    } else {
      jest.doMock('../lib/requestLogStore', () => ({ recent: async () => events.map(row => ({
        ip_address: row.ip, path: row.path, status: row.status, created_at: row.timestamp, response_time_ms: 10
      })) }));
    }
    await run();
    const manager = require('../lib/blacklistManager');
    expect(await manager.isBlocked('203.0.113.1')).toBe(true);
    await manager.unblock('203.0.113.1');
    await run();
    expect(await manager.isBlocked('203.0.113.1')).toBe(false);
  });

  test('missing and invalid timestamps cannot mint fresh evidence', async () => {
    fs.writeFileSync(process.env.AIWAF_MIDDLEWARE_LOG_PATH,
      Array.from({ length: 6 }, (_, i) => JSON.stringify({ ip: '203.0.113.1', path: '/missing.php',
        status: 404, ...(i % 2 ? { timestamp: 'invalid' } : {}) })).join('\n'));
    await run();
    await run();
    expect(await require('../lib/blacklistManager').isBlocked('203.0.113.1')).toBe(false);
  });

  test('CLI completes successfully when there are no logs', async () => {
    const previousCode = process.exitCode;
    try {
      await require('../train').runCLI();
      expect(process.exitCode).toBe(0);
    } finally { process.exitCode = previousCode; }
  });
});
