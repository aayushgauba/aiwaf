const fs = require('fs');
const os = require('os');
const path = require('path');
if (process.env.AIWAF_NATIVE_TEST_MODULE) {
  jest.doMock(require.resolve('aiwaf-wasm'), () => require(process.env.AIWAF_NATIVE_TEST_MODULE));
}
const { withTrainingEvidence } = require('../lib/trainingEvidence');

function records(offset = 0, count = 6) {
  return Array.from({ length: count }, (_, i) => ({ ip: '203.0.113.1', path: '/missing.php',
    status: '404', timestamp: new Date(Date.UTC(2026, 9, 10, 0, 0, offset + i)) }));
}

describe('real WASM training receipts', () => {
  let directory;
  beforeEach(() => { directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aiwaf-receipts-')); });
  afterEach(() => {
    if (path.dirname(directory) !== path.resolve(os.tmpdir())
        || !path.basename(directory).startsWith('aiwaf-receipts-')) throw new Error('Unsafe test cleanup');
    fs.rmSync(directory, { recursive: true, force: true });
  });

  test('restart and rotated copies cannot recreate a handled block', async () => {
    const block = jest.fn(async () => true);
    await withTrainingEvidence(directory, async ledger => {
      expect(ledger.fresh(records())).toHaveLength(6);
      expect(await ledger.block('203.0.113.1', block)).toBe(true);
      expect(await ledger.block('203.0.113.1', block)).toBe(false);
    });
    await withTrainingEvidence(directory, async ledger => {
      expect(ledger.fresh([...records().reverse(), ...records()])).toEqual([]);
      expect(await ledger.block('203.0.113.1', block)).toBe(false);
      expect(ledger.fresh([...records(), ...records(6)])).toHaveLength(6);
      expect(await ledger.block('203.0.113.1', block)).toBe(true);
    });
    expect(block).toHaveBeenCalledTimes(2);
  });

  test('exemptions and failed actions leave evidence fresh', async () => {
    await expect(withTrainingEvidence(directory, async ledger => {
      ledger.fresh(records());
      expect(await ledger.block('203.0.113.1', async () => false)).toBe(false);
      await ledger.block('203.0.113.1', async () => { throw new Error('failed'); });
    })).rejects.toThrow('failed');
    await withTrainingEvidence(directory, ledger => { expect(ledger.fresh(records())).toHaveLength(6); });
  });

  test('corrupt state fails visibly and releases the host lock', async () => {
    fs.writeFileSync(path.join(directory, 'node_training_evidence.json'), '{broken');
    await expect(withTrainingEvidence(directory, () => {})).rejects.toBeDefined();
    expect(fs.existsSync(path.join(directory, 'node_training_evidence.lock'))).toBe(false);
  });

  test('concurrent trainers load receipts after the preceding run commits', async () => {
    let ready, release;
    const started = new Promise(resolve => { ready = resolve; });
    const wait = new Promise(resolve => { release = resolve; });
    const first = withTrainingEvidence(directory, async ledger => {
      ledger.fresh(records());
      ready();
      await wait;
      await ledger.block('203.0.113.1', async () => true);
    });
    await started;
    const second = withTrainingEvidence(directory, ledger => { expect(ledger.fresh(records())).toEqual([]); });
    release();
    await Promise.all([first, second]);
  });

  test('an abandoned lock fails closed instead of allowing overlapping writes', async () => {
    fs.mkdirSync(path.join(directory, 'node_training_evidence.lock'));
    await expect(withTrainingEvidence(directory, () => {}, 5)).rejects.toThrow('confirm it has stopped');
  });
});
