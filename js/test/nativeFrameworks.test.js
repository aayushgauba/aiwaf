if (process.env.AIWAF_NATIVE_TEST_MODULE) {
  jest.doMock(require.resolve('aiwaf-wasm'), () => require(process.env.AIWAF_NATIVE_TEST_MODULE));
}
const { run, cleanup } = require('./native-frameworks-real');
test('real native framework transports inspect parsed bodies and finalize responses', async () => {
  try { await run(); } finally { await cleanup(); }
}, 30000);
