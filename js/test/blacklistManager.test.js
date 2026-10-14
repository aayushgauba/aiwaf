// The compatibility module deliberately retains its previous import path.
test('previous manager import shares the blocklist implementation', () => {
  expect(require('../lib/blacklistManager')).toBe(require('../lib/blocklistManager'));
});
