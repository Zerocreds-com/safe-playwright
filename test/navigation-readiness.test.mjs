import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import { BrowserSession } from '../src/mcp/session.mjs';

test('browser navigation returns when HTML is parsed even if a module script hangs', async (t) => {
  let moduleRequest;
  const server = http.createServer((req, res) => {
    if (req.url === '/') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<!doctype html><html><head><script type="module" src="/slow.js"></script></head><body><h1>Document is ready</h1></body></html>');
      return;
    }
    if (req.url === '/slow.js') {
      moduleRequest = res;
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    moduleRequest?.destroy();
    await new Promise((resolve) => server.close(resolve));
  });

  const session = new BrowserSession();
  t.after(() => session.close());
  const started = Date.now();
  const result = await session.navigate(`http://127.0.0.1:${server.address().port}/`, ['127.0.0.1']);

  assert.equal(result.status, 200);
  assert.ok(Date.now() - started < 5_000, 'navigation should not wait for the stalled script');
  assert.equal(await session.requirePage().locator('h1').innerText(), 'Document is ready');
});
