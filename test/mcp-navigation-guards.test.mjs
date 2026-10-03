import assert from 'node:assert/strict';
import test from 'node:test';

import { checkNavigation } from '../src/mcp/guards.mjs';

test('the full IPv6 link-local range requires an explicit allowlist entry', () => {
  for (const host of ['fe80::1', 'fe8f::1', 'fe90::1', 'fea0::1', 'febf::1']) {
    const url = `http://[${host}]/`;
    assert.equal(checkNavigation(url).ok, false, `${host} must be blocked`);
    assert.equal(checkNavigation(url, [host]).ok, true, `${host} may be explicitly allowed`);
  }
});
