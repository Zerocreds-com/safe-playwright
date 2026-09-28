#!/usr/bin/env node
// P4 demo: fill browser + storage-state handoff (issue #5).
//
// Narrative walkthrough of the same flow the test asserts:
//   local test site -> dedicated fill browser (pipe, no TCP port)
//   -> storage-state export -> agent browser born authenticated
//   -> agent-side evaluate proves the password is absent.
//
// Run: npm run demo   (never touches a real site)

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

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

const step = (number, message) => console.log(`\n[${number}] ${message}`);
const check = (label, ok) => console.log(`      ${ok ? 'PASS' : 'FAIL'}  ${label}`);

async function main() {
  const artifacts = fs.mkdtempSync(path.join(os.tmpdir(), 'safe-playwright-p4-demo-'));
  const paths = makeArtifactPaths(artifacts);
  const results = [];

  step(1, 'Starting local test login server (loopback only — no real site is contacted)');
  const server = await startLocalLoginServer({ username: USERNAME, password: SECRET });
  console.log(`      login page: ${server.url}/login`);

  step(2, 'Writing the credential to a 0600 file (the only place the password lives)');
  fs.writeFileSync(
    paths.credFile,
    `${JSON.stringify({ username: USERNAME, password: SECRET })}\n`,
    { mode: 0o600 },
  );
  fs.chmodSync(paths.credFile, 0o600);
  console.log(`      ${paths.credFile} mode=${fileMode(paths.credFile)}`);
  results.push(['credential file is 0600', fileMode(paths.credFile) === '600']);

  step(3, 'Separate OS user for the fill worker');
  const switchInfo = canSwitchUser();
  if (switchInfo.feasible) {
    console.log(`      slot user "${switchInfo.user}" — spawning worker under sudo -n -u`);
  } else {
    console.log(`      BLOCKED: ${switchInfo.blocker}`);
    console.log('      PoC falls back to same-uid execution; blocker documented in docs.');
  }
  results.push([
    'separate OS user or documented blocker',
    switchInfo.feasible || (switchInfo.blocker?.length ?? 0) > 40,
  ]);

  step(4, 'Fill browser performs the whole login (dedicated worker process)');
  const worker = spawnFillWorker({
    loginUrl: `${server.url}/login`,
    credFile: paths.credFile,
    storageOut: paths.storageOut,
    reportOut: paths.reportOut,
    switchInfo,
  });
  await worker.ready;
  console.log(`      fill worker pid ${worker.child.pid} -> HANDOFF_READY`);

  step(5, 'Independent audit while the fill browser is still open');
  const audit = auditLiveFillWorker(worker.child.pid);
  console.log(`      browser processes: ${audit.browserPids.join(', ')}`);
  console.log(`      --remote-debugging-pipe: ${audit.pipeTransport}`);
  console.log(`      --remote-debugging-port flag: ${audit.remoteDebuggingPortFlagPids.length > 0}`);
  console.log(`      listening TCP ports: ${JSON.stringify(audit.listeningTcpPorts)}`);
  results.push(['pipe transport (zero TCP ports)', audit.pipeTransport]);
  results.push(['no --remote-debugging-port', audit.remoteDebuggingPortFlagPids.length === 0]);
  results.push(['zero listening TCP ports', audit.listeningTcpPorts.length === 0]);

  worker.child.stdin.end();
  const exit = await worker.exited;
  if (exit.code !== 0) {
    console.error(`      worker failed (code ${exit.code}):\n${exit.stderr}`);
  }

  step(6, 'Fill report: hygiene (L5), storage-state, pixel policy');
  const report = readJson(paths.reportOut);
  console.log(`      hygiene: ${JSON.stringify(report.hygiene, null, 2).replace(/\n/g, '\n        ')}`);
  console.log(
    `      storage-state: mode=${report.storageState.mode} ` +
      `cookies=${report.storageState.cookieNames.join(',')} ` +
      `containsPassword=${report.storageState.containsPassword}`,
  );
  console.log(
    `      pixel export APIs called: ${JSON.stringify(report.pixelExport.forbiddenApisCalled)}`,
  );
  results.push(['fill worker self-check (report.ok)', report.ok === true]);
  results.push(['post-fill hygiene L5', report.hygiene.navigatedAfterSubmit &&
      report.hygiene.loginFormEmptyOnReturn && report.hygiene.passwordAbsentFromLoginHtml]);
  results.push(['storage-state without password', report.storageState.containsPassword === false]);
  results.push(['no pixel export', report.pixelExport.forbiddenApisCalled.length === 0]);

  step(7, 'Agent browser is born with storage-state (never sees the credential)');
  const agent = await runAgentHandoff({
    baseUrl: server.url,
    storageStatePath: paths.storageOut,
    secret: SECRET,
  });
  console.log(`      authenticated: ${agent.authenticated} ("${agent.welcomeText?.trim()}")`);
  console.log(`      agent-side evaluate password field: ${JSON.stringify(agent.passwordField)}`);
  console.log(`      password in dashboard DOM: ${agent.dashboardPasswordInDom}`);
  console.log(`      password in login DOM: ${agent.loginPasswordInDom}`);
  console.log(`      password in web storage: ${agent.storageHasSecret}`);
  console.log(`      password in cookies: ${agent.cookiesHaveSecret}`);
  results.push(['storage-state handoff authenticates agent', agent.authenticated]);
  results.push(['password absent from agent DOM (evaluate)',
    !agent.dashboardPasswordInDom && !agent.loginPasswordInDom &&
      agent.passwordField.value === '']);
  results.push(['password absent from agent storage/cookies',
    !agent.storageHasSecret && !agent.cookiesHaveSecret]);

  step(8, 'Server-side truth');
  console.log(`      ${JSON.stringify(server.stats)}`);
  results.push(['exactly one accepted login (the filler)', server.stats.acceptedLogins === 1]);

  await server.close();
  fs.rmSync(artifacts, { recursive: true, force: true });

  console.log('\n=== Acceptance summary ===');
  let failed = 0;
  for (const [label, ok] of results) {
    if (!ok) failed += 1;
    console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`);
  }
  console.log(failed === 0 ? '\nAll P4 PoC checks passed.' : `\n${failed} check(s) FAILED.`);
  process.exit(failed === 0 ? 0 : 1);
}

await main();
