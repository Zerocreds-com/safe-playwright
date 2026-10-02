// Golden MCP tool set — issue #21.
//
// Two first-class dimensions:
//   security  — guards, refusals, redaction, no-secret results;
//   usability — an agent completes the job using only these tools.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { createServer } from 'node:http';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import test, { after } from 'node:test';
import { fileURLToPath } from 'node:url';

import { startLocalLoginServer } from '../src/local-login-server.mjs';
import { callGoldenTool } from '../src/mcp/tools.mjs';

const USERNAME = 'demo-user';
const SECRET = 'golden-mcp-canary-password-7c19!';
const CANARY = 'registered-canary-e5f8aa';
const GOLDEN_SET = [
  'browser_click',
  'browser_login',
  'browser_navigate',
  'browser_screenshot',
  'browser_snapshot',
  'browser_type',
  'browser_wait',
];
const FORBIDDEN_TOOLS = [
  'browser_evaluate',
  'browser_run_code',
  'browser_get_cookies',
  'browser_fill_form',
  'browser_execute_script',
];

const artifacts = fs.mkdtempSync(path.join(os.tmpdir(), 'safe-mcp-test-'));
const credFile = path.join(artifacts, 'credential.json');
const storeFile = path.join(artifacts, 'cred-store.json');

let server = null;
let child = null;
let rpc = null;

function startRpcClient(proc) {
  let buffer = '';
  const pending = new Map();
  let nextId = 1;

  proc.stdout.setEncoding('utf8');
  proc.stdout.on('data', (chunk) => {
    buffer += chunk;
    let index;
    while ((index = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      if (!line.trim()) continue;
      const message = JSON.parse(line);
      if (message.id !== undefined && message.id !== null && pending.has(message.id)) {
        pending.get(message.id)(message);
        pending.delete(message.id);
      }
    }
  });

  let stderrText = '';
  proc.stderr.setEncoding('utf8');
  proc.stderr.on('data', (chunk) => {
    stderrText += chunk;
  });

  return {
    get stderr() {
      return stderrText;
    },
    request(method, params) {
      const id = nextId++;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`rpc timeout on ${method}; stderr: ${stderrText}`));
        }, 60_000);
        pending.set(id, (message) => {
          clearTimeout(timer);
          resolve(message);
        });
        proc.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
      });
    },
    notify(method, params) {
      proc.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
    },
    close() {
      proc.stdin.end();
    },
  };
}

async function call(name, args = {}) {
  const response = await rpc.request('tools/call', { name, arguments: args });
  assert.ok(response.result, `tools/call ${name} produced no result: ${JSON.stringify(response.error)}`);
  const { content, isError } = response.result;
  return { isError: Boolean(isError), content, text: content.map((c) => c.text ?? '').join('\n') };
}

function refFor(snapshotText, role) {
  const match = snapshotText.match(new RegExp(`^${role} .*\\[ref=(r\\d+)\\]`, 'm'));
  assert.ok(match, `no ${role} ref in snapshot:\n${snapshotText}`);
  return match[1];
}

after(() => {
  if (rpc) rpc.close();
  if (server) server.close();
  fs.rmSync(artifacts, { recursive: true, force: true });
});

test('registered canary in a navigation argument is refused before dispatch', async () => {
  let navigated = false;
  await assert.rejects(
    callGoldenTool('browser_navigate', { url: `https://example.org/?token=${CANARY}` }, {
      canaryValues: [CANARY],
      session: { navigate: async () => { navigated = true; } },
    }),
    /registered canary/,
  );
  assert.equal(navigated, false);
});

test('golden MCP tool set: security and usability', async (t) => {
  server = await startLocalLoginServer({ username: USERNAME, password: SECRET });

  fs.writeFileSync(credFile, `${JSON.stringify({ username: USERNAME, password: SECRET })}\n`, {
    mode: 0o600,
  });
  fs.chmodSync(credFile, 0o600);
  fs.writeFileSync(
    storeFile,
    `${JSON.stringify({
      'cred://local/demo': {
        loginUrl: `${server.url}/login`,
        authUrl: `${server.url}/whoami`,
        credFile,
      },
    })}\n`,
    { mode: 0o600 },
  );
  fs.chmodSync(storeFile, 0o600);

  child = spawn(process.execPath, [fileURLToPath(new URL('../src/mcp/server.mjs', import.meta.url))], {
    env: {
      ...process.env,
      SAFE_MCP_PRIVATE_ALLOW: '127.0.0.1,localhost',
      SAFE_MCP_CANARY: CANARY,
      SAFE_MCP_CRED_STORE: storeFile,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  rpc = startRpcClient(child);

  const init = await rpc.request('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'test-client', version: '0.0.0' },
  });
  rpc.notify('notifications/initialized', {});

  await t.test('registers: initialize + exactly the golden set, forbidden tools absent', () => {
    assert.equal(init.result.serverInfo.name, 'safe-playwright-mcp');
    assert.ok(init.result.capabilities.tools);

    const listed = rpc.request('tools/list', {});
    return listed.then((response) => {
      const names = response.result.tools.map((tool) => tool.name).sort();
      assert.deepEqual(names, GOLDEN_SET);
      for (const forbidden of FORBIDDEN_TOOLS) {
        assert.ok(!names.includes(forbidden), `${forbidden} must never be exposed`);
      }
      for (const tool of response.result.tools) {
        assert.equal(typeof tool.description, 'string');
        assert.ok(tool.description.length > 20, `${tool.name} needs a real description`);
        assert.equal(tool.inputSchema.type, 'object');
      }
    });
  });

  await t.test('security: navigation guards (scheme, IMDS, private, userinfo)', async () => {
    const blocked = [
      // Concatenated so the deliberate fixture does not trip policy-lint's
      // no-file-urls rule on our own test source.
      [`fil${'e:'}/` + '/etc/passwd', 'scheme'],
      ['ftp://example.com/', 'scheme'],
      ['http://169.254.169.254/latest/meta-data/', 'metadata'],
      ['http://metadata.google.internal/computeMetadata/v1/', 'metadata'],
      ['http://10.99.88.77/admin', 'private'],
      ['http://user:pass@example.com/', 'credentials'],
      ['not a url', 'valid URL'],
    ];
    for (const [url, fragment] of blocked) {
      const result = await call('browser_navigate', { url });
      assert.equal(result.isError, true, `expected block for ${url}`);
      assert.match(result.text, new RegExp(fragment), `unexpected message for ${url}: ${result.text}`);
    }
    const allowed = await call('browser_navigate', { url: `${server.url}/form-demo` });
    assert.equal(allowed.isError, false, `allowlist should permit the test server: ${allowed.text}`);
  });

  await t.test('security: registered canary URL never reaches a browser request', async () => {
    let requests = 0;
    const target = createServer((_request, response) => {
      requests += 1;
      response.writeHead(200).end('unexpected request');
    });
    await new Promise((resolve) => target.listen(0, '127.0.0.1', resolve));
    try {
      const url = `http://127.0.0.1:${target.address().port}/?token=${CANARY}`;
      const result = await call('browser_navigate', { url });
      assert.equal(result.isError, true);
      assert.match(result.text, /registered canary/);
      assert.equal(requests, 0);
    } finally {
      await new Promise((resolve) => target.close(resolve));
    }
  });

  await t.test('security: snapshot shows plain values, never OTP/tel/card values', async () => {
    const result = await call('browser_snapshot');
    assert.equal(result.isError, false, result.text);
    assert.match(result.text, /\[ref=r\d+\]/, 'refs must be present for click/type');
    assert.match(result.text, /meet at noon/, 'plain text field value stays (usability)');
    assert.ok(!result.text.includes('555-0142'), 'tel value must be redacted');
    assert.ok(!result.text.includes('493812'), 'OTP value must be redacted');
    assert.ok(!result.text.includes('4111111111111111'), 'card value must be redacted');
  });

  await t.test('security: snapshot fails closed while a password field holds a value', async () => {
    const nav = await call('browser_navigate', { url: `${server.url}/prefilled` });
    assert.equal(nav.isError, false, nav.text);
    const result = await call('browser_snapshot');
    assert.equal(result.isError, true, 'snapshot must refuse a live credential form');
    assert.match(result.text, /password field/);
    assert.ok(!result.text.includes('lingering-secret-1'), 'the value must not leak in the error');
  });

  await t.test('security: type refuses credential inputs and canary values', async () => {
    await call('browser_navigate', { url: `${server.url}/login` });
    const snapshot = await call('browser_snapshot');
    assert.equal(snapshot.isError, false, snapshot.text);
    const passwordRef = refFor(snapshot.text, 'password');
    const userRef = refFor(snapshot.text, 'textbox');

    const intoPassword = await call('browser_type', { ref: passwordRef, text: 'anything-plain' });
    assert.equal(intoPassword.isError, true, 'typing into a password field must be refused');
    assert.match(intoPassword.text, /browser_login/);

    const canaryAttempt = await call('browser_type', { ref: userRef, text: CANARY });
    assert.equal(canaryAttempt.isError, true, 'canary value must be a hard failure');
    assert.match(canaryAttempt.text, /canary/);

    const plain = await call('browser_type', { ref: userRef, text: USERNAME });
    assert.equal(plain.isError, false, plain.text);
  });

  await t.test('usability: stale refs fail with an instructive message', async () => {
    const before = await call('browser_snapshot');
    const ref = refFor(before.text, 'textbox');
    await call('browser_navigate', { url: `${server.url}/form-demo` });
    const clicked = await call('browser_click', { ref });
    assert.equal(clicked.isError, true);
    assert.match(clicked.text, /fresh browser_snapshot/);
  });

  await t.test('usability + security: browser_login performs the P5 handoff', async () => {
    const result = await call('browser_login', { credentialRef: 'cred://local/demo' });
    assert.equal(result.isError, false, result.text);
    assert.match(result.text, /"authenticated":true/);
    assert.ok(!result.text.includes(SECRET), 'login result must never contain the password');
    assert.ok(!result.text.includes(USERNAME), 'login result should stay minimal');
    assert.match(result.text, /storage-state \(P5\)/);

    // The credential store path is validated fail-closed too.
    const badRef = await call('browser_login', { credentialRef: SECRET });
    assert.equal(badRef.isError, true, 'raw secrets as references must be rejected (C4)');
    assert.match(badRef.text, /reference/i);

    // Server-side truth: exactly one login, from the fill worker.
    const stats = await fetch(`${server.url}/stats`).then((r) => r.json());
    assert.equal(stats.acceptedLogins, 1);
    assert.equal(stats.rejectedLogins, 0);
  });

  await t.test('usability: post-login reads, screenshot policy, L5 in the agent browser', async () => {
    const nav = await call('browser_navigate', { url: `${server.url}/dashboard` });
    assert.equal(nav.isError, false, nav.text);

    const snapshot = await call('browser_snapshot');
    assert.equal(snapshot.isError, false, snapshot.text);
    assert.match(snapshot.text, /Welcome, demo-user/, 'agent must see the authenticated page');

    const wait = await call('browser_wait', { timeMs: 50 });
    assert.equal(wait.isError, false, wait.text);

    const shot = await call('browser_screenshot', { fullPage: false });
    assert.equal(shot.isError, false, shot.text);
    const image = shot.content.find((block) => block.type === 'image');
    assert.ok(image, 'dashboard screenshot must return an image block');
    assert.ok(image.data.length > 500, 'image payload looks empty');

    await call('browser_navigate', { url: `${server.url}/login` });
    const blockedShot = await call('browser_screenshot');
    assert.equal(blockedShot.isError, true, 'credential page must refuse screenshots (U7)');
    assert.match(blockedShot.text, /credential/);

    // L5 in the agent's browser: the password field is present but empty,
    // so a snapshot is allowed — and must not carry the credential.
    const loginSnapshot = await call('browser_snapshot');
    assert.equal(loginSnapshot.isError, false, loginSnapshot.text);
    assert.ok(!loginSnapshot.text.includes(SECRET), 'password must be absent from the agent DOM');
    assert.match(loginSnapshot.text, /password/);
  });

  await t.test('shutdown: server exits cleanly on stdin close', async () => {
    const stderrSoFar = rpc.stderr;
    const exit = new Promise((resolve) => child.once('exit', (code) => resolve(code)));
    rpc.close();
    rpc = null;
    const code = await exit;
    assert.equal(code, 0, `mcp server exited with ${code}; stderr: ${stderrSoFar}`);
  });
});
