const test = require('node:test'), assert = require('node:assert');
const L = require('../mcp-advisory-flag.user.js');
const ds = require('./fixtures/dataset.json'), osv = require('./fixtures/osv-mcp-remote.json');
test('npm url parse', () => {
  assert.equal(L.npmNameFromUrl('https://www.npmjs.com/package/mcp-remote'), 'mcp-remote');
  assert.equal(L.npmNameFromUrl('https://www.npmjs.com/package/@modelcontextprotocol/sdk?activeTab=versions'), '@modelcontextprotocol/sdk');
  assert.equal(L.npmNameFromUrl('https://www.npmjs.com/search?q=mcp'), null);
});
test('github url parse', () => {
  assert.deepEqual(L.githubRepoFromUrl('https://github.com/geelen/mcp-remote'), { owner: 'geelen', repo: 'mcp-remote' });
  assert.equal(L.githubRepoFromUrl('https://github.com/orgs/foo'), null);
  assert.equal(L.githubRepoFromUrl('https://github.com/a/b/issues/3'), null);
});
test('mcp-remote flagged, dataset+OSV deduped', () => {
  const l = L.mergeOsv(L.matchDataset(ds, 'mcp-remote', 'npm'), osv.vulns);
  assert.equal(l.length, 1); assert.equal(l[0].id, 'GHSA-6xpm-ggf7-wc3p');
});
test('clean package not flagged', () => { assert.equal(L.badgeText(L.mergeOsv(L.matchDataset(ds, 'left-pad-xyz', 'npm'), []), false), null); });
test('free hides fix version, pro shows it', () => {
  const l = [{ id: 'X', severity: 'HIGH', fixed: '0.1.16' }, { id: 'Y', severity: 'LOW', fixed: '0.1.9' }];
  assert.ok(!L.badgeText(l, false).includes('upgrade')); assert.match(L.badgeText(l, true), /upgrade to \u2265 0\.1\.16/);
});
test('osv fixed extraction', () => { assert.ok(L.fixedFromOsv(osv.vulns[0])); });
test('license states', () => {
  assert.equal(L.licenseState({ success: true, purchase: {} }).pro, true);
  assert.equal(L.licenseState({ success: false }).pro, false);
  assert.equal(L.licenseState({ success: true, purchase: { refunded: true } }).pro, false);
  assert.equal(L.licenseState({ success: true, purchase: { subscription_ended_at: 'x' } }).pro, false);
});
