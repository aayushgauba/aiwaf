const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const csv = require('../lib/csvStore');

describe('CSV mutations', () => {
  let dir, file;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aiwaf-csv-mutation-'));
    file = path.join(dir, 'blocks.csv');
  });
  afterEach(() => {
    jest.restoreAllMocks();
    if (path.dirname(dir) !== os.tmpdir() || !path.basename(dir).startsWith('aiwaf-csv-mutation-')) {
      throw new Error('Unexpected test directory');
    }
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('separate writers keep all rows', async () => {
    const source = `const csv = require(${JSON.stringify(require.resolve('../lib/csvStore'))});
      (async () => { for(let i=0;i<10;i++) await csv.updateRows(process.argv[1], ['ip'],
        rows => ({rows:[...rows,{ip:process.argv[2]+i}]})); })().catch(e=>{console.error(e);process.exitCode=1});`;
    const workers = ['one-', 'two-', 'three-'].map(prefix => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['-e', source, file, prefix]);
      let errors = '';
      child.stderr.on('data', output => { errors += output; });
      child.on('error', reject);
      child.on('exit', code => code === 0 ? resolve() : reject(new Error(errors)));
    }));
    await Promise.all(workers);
    expect(csv.readRows(file, ['ip'])).toHaveLength(30);
  }, 30000);

  test('mutation failure releases the lock without replacing data', async () => {
    csv.writeRows(file, ['ip'], [{ ip: 'old' }]);
    await expect(csv.updateRows(file, ['ip'], () => { throw new Error('failed'); })).rejects.toThrow('failed');
    expect(fs.existsSync(`${file}.lock`)).toBe(false);
    expect(csv.readRows(file, ['ip'])).toEqual([{ ip: 'old' }]);
    jest.spyOn(fs, 'renameSync').mockImplementation(() => { throw new Error('rename failed'); });
    await expect(csv.updateRows(file, ['ip'], () => ({ rows: [{ ip: 'new' }] }))).rejects.toThrow('rename failed');
    expect(fs.readdirSync(dir)).toEqual(['blocks.csv']);
    expect(csv.readRows(file, ['ip'])).toEqual([{ ip: 'old' }]);
  });

  test('lock timeout and access failure do not break another writer lock', async () => {
    fs.mkdirSync(`${file}.lock`);
    await expect(csv.updateRows(file, ['ip'], () => ({ rows: [] }), 0)).rejects.toThrow('lock timeout');
    expect(fs.existsSync(`${file}.lock`)).toBe(true);
    fs.rmdirSync(`${file}.lock`);
    jest.spyOn(fs, 'mkdirSync').mockImplementation(() => { throw Object.assign(new Error('denied'), { code: 'EACCES' }); });
    await expect(csv.updateRows(file, ['ip'], () => ({ rows: [] }))).rejects.toThrow('denied');
  });
});
