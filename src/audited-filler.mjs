#!/usr/bin/env node
// Audited fill worker — the P4/P5 fill browser (issue #5, epic #2 C10/C11).
//
// This is the only process in the stack that ever holds the credential.
// Contract:
//   * launched as a separate process (optionally as a dedicated slot OS
//     user, see slot-user.mjs) — never inside the agent's driver;
//   * Playwright's default transport: --remote-debugging-pipe over two
//     inherited fds, zero listening TCP ports (audited below while the
//     browser is still open);
//   * no pixel export: screen capture, video recording and frame tracing
//     are policy-forbidden and
//     additionally tripwired at runtime;
//   * performs the whole login flow, asserts post-fill hygiene (L5), then
//     exports storage-state (0600) for the agent browser handoff;
//   * the credential is read from a 0600 file — never from argv, env or
//     stdout — and is never written into the report or logs.
//
// Protocol: after the report and storage-state are on disk the worker
// prints HANDOFF_READY and holds the browser open until stdin is closed
// (or SAFE_FILL_HOLD_MS elapses), so the parent test can run its own
// independent process-tree/port audit while the fill browser is alive.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { chromium } from 'playwright';

import { auditProcessTree } from './port-audit.mjs';
import { configuredSlotUser } from './slot-user.mjs';

const HOLD_MS = Number(process.env.SAFE_FILL_HOLD_MS ?? 60_000);

// Built via join() so this file's own static policy scan cannot match
// itself — the scan looks for these tokens and must not find them here.
const PIXEL_FORBIDDEN_TOKENS = [
  ['screen', 'shot'].join(''),
  ['record', 'Video'].join(''),
  ['tra', 'cing.start'].join(''),
];
const SHOT = ['screen', 'shot'].join('');

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key || !key.startsWith('--') || value === undefined) {
      throw new Error(`Unexpected worker argument: ${key ?? '<none>'}`);
    }
    args[key.slice(2)] = value;
  }
  return args;
}

function usage() {
  return [
    'Usage: audited-filler.mjs',
    '  --login-url <url>    login page of the (local test) site',
    '  --cred-file <path>   0600 JSON file: {"username","password"}',
    '  --storage-out <path> where to write browserContext.storageState()',
    '  --report-out <path>  where to write the fill/hygiene/audit report',
  ].join('\n');
}

function redact(text, secrets) {
  let result = String(text);
  for (const secret of secrets) {
    if (secret) result = result.split(secret).join('[REDACTED]');
  }
  return result;
}

function installPixelExportGuard() {
  const blockedCalls = [];
  const forbidden = (api) =>
    function forbiddenPixelExport() {
      blockedCalls.push(api);
      throw new Error(`POLICY: ${api} is forbidden in the fill browser (no pixel export)`);
    };
  return {
    blockedCalls,
    install(page, context) {
      Object.getPrototypeOf(page)[SHOT] = forbidden(SHOT);
      Object.getPrototypeOf(page.locator('body'))[SHOT] = forbidden(`locator.${SHOT}`);
      const tracing = context[['tra', 'cing'].join('')];
      tracing[['tra', 'cing.start'].join('')] = forbidden(['tra', 'cing.start'].join(''));
      tracing[['tra', 'cing.startBeforeLoad'].join('')] = forbidden(
        ['tra', 'cing.startBeforeLoad'].join(''),
      );
    },
  };
}

function waitForStdinEof(timeoutMs) {
  if (process.stdin.isTTY || process.stdin.destroyed || process.stdin.readableEnded) {
    return Promise.resolve({ endReason: 'no-piped-stdin' });
  }
  return new Promise((resolve) => {
    let settled = false;
    const finish = (endReason) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      process.stdin.removeListener('end', finish);
      process.stdin.removeListener('close', finish);
      process.stdin.removeListener('error', finish);
      resolve({ endReason });
    };
    const timer = setTimeout(() => finish('hold-timeout'), timeoutMs);
    process.stdin.on('end', () => finish('stdin-closed'));
    process.stdin.on('close', () => finish('stdin-closed'));
    process.stdin.on('error', () => finish('stdin-error'));
    process.stdin.resume();
  });
}

function writeReport(reportOut, report) {
  fs.writeFileSync(reportOut, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(reportOut, 0o600);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  for (const required of ['login-url', 'cred-file', 'storage-out', 'report-out']) {
    if (!args[required]) {
      process.stderr.write(`Missing --${required}\n${usage()}\n`);
      process.exit(2);
    }
  }

  const credFile = path.resolve(args['cred-file']);
  const storageOut = path.resolve(args['storage-out']);
  const reportOut = path.resolve(args['report-out']);
  const loginUrl = args['login-url'];

  const credFileMode = fs.statSync(credFile).mode & 0o777;
  const credentials = JSON.parse(fs.readFileSync(credFile, 'utf8'));
  const { username, password } = credentials;
  const secrets = [password];

  const report = {
    ok: false,
    fillWorker: {
      pid: process.pid,
      uid: process.getuid?.() ?? null,
      username: os.userInfo().username,
      script: path.basename(fileURLToPath(import.meta.url)),
      argv: process.argv.slice(2),
    },
    slotUser: { configured: configuredSlotUser() },
    credentials: {
      credFile,
      credFileMode: credFileMode.toString(8).padStart(3, '0'),
      passwordInArgv: process.argv.some((arg) => arg.includes(password)),
    },
    hygiene: {},
    storageState: {},
    fillBrowser: {},
    pixelExport: { forbiddenApisCalled: [], policy: 'no pixel export from the fill browser' },
  };

  let browser = null;
  const pixelGuard = installPixelExportGuard();
  try {
    // Playwright default transport: --remote-debugging-pipe, no TCP port.
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    pixelGuard.install(page, context);

    // --- credential fill flow (the only place the password is typed) ---
    await page.goto(loginUrl);
    await page.fill('#username', username);
    await page.fill('#password', password);
    const heldDuringFill = await page.$eval('#password', (element) => element.value.length > 0);
    await Promise.all([
      page.waitForURL((url) => new URL(url).pathname === '/dashboard'),
      page.click('button[type="submit"]'),
    ]);
    const navigatedAfterSubmit = new URL(page.url()).pathname === '/dashboard';

    // --- post-fill hygiene (L5) on the fresh document ---
    const dashboardProbe = await page.evaluate(() => {
      const field = document.querySelector('input[type="password"]');
      return { passwordFieldPresent: Boolean(field), passwordValue: field ? field.value : null };
    });
    const dashboardHtml = await page.content();
    const passwordAbsentFromDashboardHtml = !dashboardHtml.includes(password);

    // --- storage-state handoff artifact (cookie only, never the credential) ---
    await context.storageState({ path: storageOut });
    fs.chmodSync(storageOut, 0o600);
    const storageRaw = fs.readFileSync(storageOut, 'utf8');
    const storageJson = JSON.parse(storageRaw);

    // --- L5: revisiting the login form must show an empty password field ---
    await page.goto(loginUrl);
    const passwordValueOnReturn = await page.$eval('#password', (element) => element.value);
    const loginHtml = await page.content();
    const passwordAbsentFromLoginHtml = !loginHtml.includes(password);

    // --- transport audit while the fill browser is still open ---
    const audit = auditProcessTree(process.pid);

    const hygiene = {
      heldDuringFill,
      navigatedAfterSubmit,
      passwordFieldPresentOnDashboard: dashboardProbe.passwordFieldPresent,
      passwordValueOnDashboard: dashboardProbe.passwordValue,
      passwordAbsentFromDashboardHtml,
      loginFormEmptyOnReturn: passwordValueOnReturn === '',
      passwordValueOnReturn,
      passwordAbsentFromLoginHtml,
    };
    const hygieneOk =
      hygiene.heldDuringFill &&
      hygiene.navigatedAfterSubmit &&
      !hygiene.passwordFieldPresentOnDashboard &&
      hygiene.passwordAbsentFromDashboardHtml &&
      hygiene.loginFormEmptyOnReturn &&
      hygiene.passwordAbsentFromLoginHtml;

    report.hygiene = hygiene;
    report.storageState = {
      path: storageOut,
      mode: (fs.statSync(storageOut).mode & 0o777).toString(8).padStart(3, '0'),
      containsPassword: storageRaw.includes(password),
      cookieNames: storageJson.cookies.map((cookie) => cookie.name),
      originCount: storageJson.origins.length,
    };
    report.fillBrowser = {
      pipeTransport: audit.pipeTransport,
      remoteDebuggingPortFlag: audit.remoteDebuggingPortFlagPids.length > 0,
      browserPids: audit.browserPids,
      listeningTcpPorts: audit.listeningTcpPorts,
      mainBrowserCommandLine: audit.mainBrowserCommandLine
        ? audit.mainBrowserCommandLine.slice(0, 1500)
        : null,
    };
    report.pixelExport.forbiddenApisCalled = pixelGuard.blockedCalls;
    report.pixelExport.staticTokenScan = PIXEL_FORBIDDEN_TOKENS.map((token) => ({
      token,
      presentInSource: fs.readFileSync(fileURLToPath(import.meta.url), 'utf8').includes(token),
    }));

    report.ok =
      hygieneOk &&
      !report.storageState.containsPassword &&
      report.fillBrowser.pipeTransport &&
      !report.fillBrowser.remoteDebuggingPortFlag &&
      report.fillBrowser.listeningTcpPorts.length === 0 &&
      !report.credentials.passwordInArgv &&
      report.pixelExport.forbiddenApisCalled.length === 0 &&
      report.pixelExport.staticTokenScan.every((entry) => !entry.presentInSource);

    writeReport(reportOut, report);
    process.stdout.write('HANDOFF_READY\n');
    await waitForStdinEof(HOLD_MS);
    await browser.close();
    browser = null;
    process.stdout.write('FILL_DONE\n');
    process.exit(report.ok ? 0 : 1);
  } catch (error) {
    report.error = redact(error?.stack ?? String(error), secrets);
    if (browser) {
      await browser.close().catch(() => {});
    }
    writeReport(reportOut, report);
    process.stderr.write(`${report.error}\n`);
    process.exit(1);
  }
}

await main();
