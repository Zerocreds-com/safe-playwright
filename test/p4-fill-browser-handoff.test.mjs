// P4 PoC: fill browser + storage-state handoff (issue #5, epic #2).
//
// One flow, asserted end to end against a local test login server:
//   1. a dedicated fill worker performs the whole login (credential
//      fill) in its own process over Playwright's default pipe;
//   2. the fill browser process tree has zero listening TCP ports and no
//      --remote-debugging-port flag (independent audit, browser alive);
//   3. post-fill hygiene (L5): navigation happened, no password field or
//      password value survives in the DOM afterwards;
//   4. storage-state (0600, cookie only) is handed to an agent browser;
//   5. the agent browser is authenticated without ever seeing the
//      credential — agent-side evaluate proves the password is absent;
//   6. separate OS user for the filler, or a documented blocker.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test, { after } from 'node:test';

import { canSwitchUser } from '../src/slot-user.mjs';
import { startLocalLoginServer } from '../src/local-login-server.mjs';
import {
  auditLiveFillWorker,
  fileMode,
  makeArtifactPaths,
  readJson,
  runAgentHandoff,
  spawnFillWorker,
} from '../src/handoff-runner.mjs';

const USERNAME = 'demo-user';
const SECRET = 'P4-canary-password-9f3a7c21!';

const artifacts = fs.mkdtempSync(path.join(os.tmpdir(), 'safe-playwright-p4-'));
const paths = makeArtifactPaths(artifacts);

let server = null;
let switchInfo = null;

function writeCredentialFile() {
  fs.writeFileSync(paths.credFile, `${JSON.stringify({ username: USERNAME, password: SECRET })}\n`, {
    mode: 0o600,
  });
  fs.chmodSync(paths.credFile, 0o600);
}

after(async () => {
  if (server) await server.close();
  fs.rmSync(artifacts, { recursive: true, force: true });
});

test('P4: fill browser login, zero TCP ports, storage-state handoff to agent browser', async (t) => {
  server = await startLocalLoginServer({ username: USERNAME, password: SECRET });
  writeCredentialFile();
  switchInfo = canSwitchUser();

  await t.test('credential file is 0600 and the worker argv carries no secret', async () => {
    assert.equal(fileMode(paths.credFile), '600');
  });

  await t.test('test login server binds loopback only', () => {
    assert.ok(
      server.url.startsWith('http://127.0.0.1:'),
      `test server must bind loopback, got ${server.url}`,
    );
  });

  await t.test('fill worker performs the login and holds the browser open for audit', async () => {
    const worker = spawnFillWorker({
      loginUrl: `${server.url}/login`,
      credFile: paths.credFile,
      storageOut: paths.storageOut,
      reportOut: paths.reportOut,
      switchInfo,
    });
    await worker.ready;

    // While the fill browser is alive: independent process-tree audit.
    const audit = auditLiveFillWorker(worker.child.pid);

    assert.ok(audit.browserPids.length > 0, 'fill browser processes must exist');
    assert.ok(
      audit.pipeTransport,
      'fill browser must be launched with Playwright default --remote-debugging-pipe',
    );
    assert.equal(
      audit.remoteDebuggingPortFlagPids.length,
      0,
      'fill browser must not carry --remote-debugging-port',
    );
    assert.deepEqual(
      audit.listeningTcpPorts,
      [],
      'fill browser process tree must have zero listening TCP ports',
    );

    // Password must not travel in argv (cred file path only).
    const workerPs = execFileSync('ps', ['-o', 'command=', '-p', String(worker.child.pid)], {
      encoding: 'utf8',
    });
    assert.ok(!workerPs.includes(SECRET), 'worker argv must not contain the password');

    // Release the worker: closing stdin lets it close the browser and exit.
    worker.child.stdin.end();
    const exit = await worker.exited;
    assert.equal(exit.code, 0, `fill worker must exit cleanly, stderr:\n${exit.stderr}`);
    assert.ok(exit.stdout.includes('FILL_DONE'));
  });

  await t.test('report: post-fill hygiene (L5), pipe transport, no pixel export', async () => {
    const report = readJson(paths.reportOut);
    assert.equal(report.ok, true, `worker self-check failed: ${report.error ?? ''}`);

    // Fill flow
    assert.equal(report.hygiene.heldDuringFill, true, 'password was held by the page during fill');
    assert.equal(report.hygiene.navigatedAfterSubmit, true, 'submit must navigate (L5)');

    // L5 hygiene: nothing left behind after navigation and on re-entry
    assert.equal(report.hygiene.passwordFieldPresentOnDashboard, false);
    assert.equal(report.hygiene.passwordValueOnDashboard, null);
    assert.equal(report.hygiene.passwordAbsentFromDashboardHtml, true);
    assert.equal(report.hygiene.loginFormEmptyOnReturn, true);
    assert.equal(report.hygiene.passwordValueOnReturn, '');
    assert.equal(report.hygiene.passwordAbsentFromLoginHtml, true);

    // Transport: pipe only, no TCP port (worker-side audit, browser alive)
    assert.equal(report.fillBrowser.pipeTransport, true);
    assert.equal(report.fillBrowser.remoteDebuggingPortFlag, false);
    assert.deepEqual(report.fillBrowser.listeningTcpPorts, []);

    // Policy: no pixel export APIs touched
    assert.deepEqual(report.pixelExport.forbiddenApisCalled, []);
    for (const entry of report.pixelExport.staticTokenScan) {
      assert.equal(entry.presentInSource, false, `fill worker source must not use ${entry.token}`);
    }

    // Credential plumbing
    assert.equal(report.credentials.passwordInArgv, false);
    assert.equal(report.credentials.credFileMode, '600');
  });

  await t.test('storage-state handoff artifact: 0600, session cookie, no password', async () => {
    assert.equal(fileMode(paths.storageOut), '600');
    const report = readJson(paths.reportOut);
    assert.equal(report.storageState.mode, '600');
    assert.equal(report.storageState.containsPassword, false);
    assert.ok(report.storageState.cookieNames.includes('session'));

    const raw = fs.readFileSync(paths.storageOut, 'utf8');
    assert.ok(!raw.includes(SECRET), 'storage-state must never contain the credential');
    const parsed = JSON.parse(raw);
    assert.ok(parsed.cookies.length > 0, 'handoff must carry the session cookie');
  });

  await t.test('fill browser runs as a different OS user, or the blocker is documented', async () => {
    const report = readJson(paths.reportOut);
    if (switchInfo.feasible) {
      assert.notEqual(
        report.fillWorker.uid,
        process.getuid(),
        'fill worker must run under the slot OS user',
      );
      assert.equal(report.slotUser.configured, switchInfo.user);
    } else {
      // Acceptance alternative: a documented blocker. It must be concrete,
      // and the PoC docs must carry it (checked below).
      assert.equal(typeof switchInfo.blocker, 'string');
      assert.ok(switchInfo.blocker.length > 40, 'blocker must be a specific explanation');
      assert.equal(report.fillWorker.uid, process.getuid(), 'fallback: same-uid execution');
      const docs = [
        'README.md',
        'docs/p4-fill-browser-storage-state-handoff-poc.md',
      ].map((file) => fs.readFileSync(new URL(`../${file}`, import.meta.url), 'utf8'));
      const documented = docs.some(
        (text) => text.includes('slot user') || text.includes('separate OS user'),
      );
      assert.ok(documented, 'the OS-user blocker must be documented in README/docs');
    }
  });

  await t.test('agent browser is authenticated, password absent from DOM/evaluate', async () => {
    const agent = await runAgentHandoff({
      baseUrl: server.url,
      storageStatePath: paths.storageOut,
      secret: SECRET,
    });

    // Handoff works: authenticated without seeing the credential
    assert.equal(agent.authenticated, true, 'agent must be authenticated via storage-state');
    assert.ok(agent.welcomeText.includes(USERNAME));
    assert.equal(agent.sessionCookiePresent, true);

    // Agent-side evaluate proves the password is absent
    assert.equal(agent.dashboardPasswordInDom, false, 'password must not be in the dashboard DOM');
    assert.equal(agent.loginPasswordInDom, false, 'password must not be in the login page DOM');
    assert.ok(
      agent.passwordField.present,
      'login page must still expose an empty password field',
    );
    assert.equal(
      agent.passwordField.value,
      '',
      'agent-side evaluate: password field must be empty',
    );
    assert.equal(agent.storageHasSecret, false, 'no web storage may carry the credential');
    assert.equal(agent.cookiesHaveSecret, false, 'no cookie may carry the credential');
    assert.ok(!agent.cookieNames.includes('password'));
  });

  await t.test('server-side truth: exactly one accepted login from the filler', async () => {
    const stats = server.stats;
    assert.equal(stats.acceptedLogins, 1, 'only the fill browser may log in');
    assert.equal(stats.rejectedLogins, 0);
  });
});
