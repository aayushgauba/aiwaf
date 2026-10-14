const fs = require('fs');
const path = require('path');
const os = require('os');

async function runIsolatedTraining() {
  let train;
  jest.isolateModules(() => { train = require('../train'); });
  await train();
}

function writeLog(lines) {
  const dir = path.join(process.cwd(), 'logs', 'train-tests');
  fs.mkdirSync(dir, { recursive: true });
  const filePath = path.join(dir, `access-${Date.now()}-${Math.random().toString(36).slice(2)}.log`);
  fs.writeFileSync(filePath, lines.join('\n') + '\n', 'utf8');
  return filePath;
}

function makeLine(ip, pathVal, status = 404) {
  return `${ip} - - [10/Oct/2020:13:55:36 +0000] "GET ${pathVal} HTTP/1.1" ${status} 123 "-" "-" response-time=0.1`;
}

describe('trainer parity', () => {
  let stateDirectory;
  beforeEach(() => {
    jest.resetModules();
    stateDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'aiwaf-train-'));
    process.env.AIWAF_TRAINING_STATE_DIR = stateDirectory;
    if (process.env.AIWAF_NATIVE_TEST_MODULE) {
      jest.doMock(require.resolve('aiwaf-wasm'), () => require(process.env.AIWAF_NATIVE_TEST_MODULE));
    }
  });

  afterEach(() => {
    if (path.dirname(stateDirectory) !== path.resolve(os.tmpdir())
        || !path.basename(stateDirectory).startsWith('aiwaf-train-')) throw new Error('Unsafe test cleanup');
    fs.rmSync(stateDirectory, { recursive: true, force: true });
    delete process.env.AIWAF_TRAINING_STATE_DIR;
    delete process.env.AIWAF_MIDDLEWARE_LOG_PATH;
    delete process.env.AIWAF_MIDDLEWARE_LOG_CSV_PATH;
  });

  it('reads JSONL, CSV, and database middleware event fallbacks', async () => {
    const missingAccessPath = path.join(process.cwd(), 'logs', `missing-${Date.now()}.log`);
    const jsonlPath = `${missingAccessPath}.jsonl`;
    const csvPath = `${missingAccessPath}.csv`;
    fs.writeFileSync(jsonlPath, `${JSON.stringify({
      timestamp: new Date().toISOString(), ip: '203.0.113.21', path: '/jsonl?x=1', status: 200
    })}\nmalformed\n`, 'utf8');
    fs.writeFileSync(csvPath,
      'timestamp,ip,method,path,status,responseTime\n2026-01-01T00:00:00Z,203.0.113.22,GET,/csv,200,3\n',
      'utf8');
    process.env.AIWAF_ACCESS_LOG = missingAccessPath;
    process.env.AIWAF_MIN_TRAIN_LOGS = '1';
    process.env.AIWAF_MIN_AI_LOGS = '10000';

    const recent = jest.fn(async () => [{
        ip_address: '203.0.113.23', path: '/db', status: 200,
        response_time_ms: 4, created_at: new Date().toISOString()
      }]);
    jest.doMock('../lib/requestLogStore', () => ({ recent }));
    jest.doMock('../lib/modelStore', () => ({ save: jest.fn(async () => {}) }));
    jest.doMock('../lib/dynamicKeywordStore', () => ({ add: jest.fn(), remove: jest.fn() }));
    jest.doMock('../lib/exemptionStore', () => ({
      initialize: jest.fn(), listPaths: jest.fn(async () => []), listIps: jest.fn(async () => [])
    }));
    jest.doMock('../lib/blacklistManager', () => ({
      unblock: jest.fn(), block: jest.fn(), getBlockedIPs: jest.fn(async () => [])
    }));

    const runTrainer = async (jsonPath, csvEventPath) => {
      process.env.AIWAF_MIDDLEWARE_LOG_PATH = jsonPath;
      process.env.AIWAF_MIDDLEWARE_LOG_CSV_PATH = csvEventPath;
      await runIsolatedTraining();
      jest.resetModules();
    };

    await runTrainer(jsonlPath, `${csvPath}.missing`);
    await runTrainer(`${jsonlPath}.missing`, csvPath);
    await runTrainer(`${jsonlPath}.missing`, `${csvPath}.missing`);
    expect(recent).toHaveBeenCalled();
  });

  it('learns keywords when AI training is skipped', async () => {
    const logPath = writeLog([
      makeLine('203.0.113.1', '/wp-admin/secret'),
      makeLine('203.0.113.1', '/wp-admin/secret'),
      makeLine('203.0.113.1', '/.env')
    ]);

    process.env.AIWAF_ACCESS_LOG = logPath;
    process.env.AIWAF_MIN_TRAIN_LOGS = '1';
    process.env.AIWAF_MIN_AI_LOGS = '10000';
    process.env.AIWAF_ENABLE_KEYWORD_LEARNING = 'true';
    process.env.AIWAF_DYNAMIC_TOP_N = '2';
    process.env.AIWAF_EXEMPT_KEYWORDS = 'admin';

    const add = jest.fn(async () => {});
    const remove = jest.fn(async () => {});

    jest.doMock('../lib/modelStore', () => ({ save: jest.fn(async () => {}) }));
    jest.doMock('../lib/dynamicKeywordStore', () => ({ add, remove }));
    jest.doMock('../lib/exemptionStore', () => ({
      initialize: jest.fn(async () => {}),
      listPaths: jest.fn(async () => []),
      listIps: jest.fn(async () => [])
    }));
    jest.doMock('../lib/blacklistManager', () => ({
      unblock: jest.fn(async () => {}),
      block: jest.fn(async () => {}),
      getBlockedIPs: jest.fn(async () => [])
    }));

    await runIsolatedTraining();

    expect(add).toHaveBeenCalled();
    expect(remove).toHaveBeenCalledWith('admin');
  });

  it('blocks excessive non-login 404s and unblocks exempt IPs', async () => {
    const lines = [];
    for (let i = 0; i < 6; i++) {
      lines.push(makeLine('203.0.113.2', `/wp-admin/scan-${i}`));
      lines.push(makeLine('203.0.113.3', `/login/scan-${i}`));
    }
    const logPath = writeLog(lines);

    process.env.AIWAF_ACCESS_LOG = logPath;
    process.env.AIWAF_MIN_TRAIN_LOGS = '1';
    process.env.AIWAF_MIN_AI_LOGS = '10000';
    process.env.AIWAF_LOGIN_PATH_PREFIXES = '/login/';

    const block = jest.fn(async () => {});
    const unblock = jest.fn(async () => {});

    jest.doMock('../lib/modelStore', () => ({ save: jest.fn(async () => {}) }));
    jest.doMock('../lib/dynamicKeywordStore', () => ({ add: jest.fn(async () => {}), remove: jest.fn(async () => {}) }));
    jest.doMock('../lib/exemptionStore', () => ({
      initialize: jest.fn(async () => {}),
      listPaths: jest.fn(async () => []),
      listIps: jest.fn(async () => [{ ip_address: '203.0.113.3' }])
    }));
    jest.doMock('../lib/blacklistManager', () => ({
      unblock,
      block,
      getBlockedIPs: jest.fn(async () => [])
    }));

    await runIsolatedTraining();

    expect(unblock).toHaveBeenCalledWith('203.0.113.3');
    expect(block).toHaveBeenCalledWith('203.0.113.2', expect.stringContaining('Excessive 404s'));
  });

  it('trains model when sufficient logs are present', async () => {
    const logPath = writeLog([
      makeLine('203.0.113.5', '/safe', 200),
      makeLine('203.0.113.5', '/safe', 200),
      makeLine('203.0.113.5', '/safe', 200)
    ]);

    process.env.AIWAF_ACCESS_LOG = logPath;
    process.env.AIWAF_MIN_TRAIN_LOGS = '1';
    process.env.AIWAF_MIN_AI_LOGS = '1';

    const save = jest.fn(async () => {});

    jest.doMock('../lib/modelStore', () => ({ save }));
    jest.doMock('../lib/dynamicKeywordStore', () => ({ add: jest.fn(async () => {}), remove: jest.fn(async () => {}) }));
    jest.doMock('../lib/exemptionStore', () => ({
      initialize: jest.fn(async () => {}),
      listPaths: jest.fn(async () => []),
      listIps: jest.fn(async () => [])
    }));
    jest.doMock('../lib/blacklistManager', () => ({
      unblock: jest.fn(async () => {}),
      block: jest.fn(async () => {}),
      getBlockedIPs: jest.fn(async () => [])
    }));

    await runIsolatedTraining();

    expect(save).toHaveBeenCalled();
  });
});
