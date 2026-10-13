// Real engine checks enter Node adapter code under coverage; no mocked WASM fallback.
if (process.env.AIWAF_NATIVE_TEST_MODULE) {
  // Load actual generated CommonJS bindings: Jest cannot import bundler WASM assets.
  jest.doMock(require.resolve('aiwaf-wasm'), () => require(process.env.AIWAF_NATIVE_TEST_MODULE));
}
const { run, cleanup } = require('./native-pipeline-real');
test('real native request pipeline security and lifecycle', async () => {
  try { await run(); } finally { cleanup(); }
}, 30000);
