const fs = require('fs');
const os = require('os');
const path = require('path');
test('explicit native startup rejects an unavailable WASM runtime without a JS fallback', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aiwaf-unavailable-'));
  jest.resetModules();
  // Register by the resolved module identity before masking fallback filesystem files.
  jest.doMock(require.resolve('aiwaf-wasm'), () => { throw new Error('fixture unavailable'); });
  const exists = fs.existsSync;
  const existsSpy = jest.spyOn(fs, 'existsSync').mockImplementation(file =>
    String(file).includes('aiwaf-wasm') && String(file).includes('node_modules') ? false : exists(file));
  try {
    const createNative = require('../lib/nativePipeline');
    await expect(createNative({ dataDir: root })).rejects.toThrow(/requires aiwaf-wasm/);
  } finally {
    jest.dontMock(require.resolve('aiwaf-wasm'));
    existsSpy.mockRestore();
    fs.rmSync(root, { recursive: true, force: true });
  }
});
