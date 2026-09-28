// Shared orchestration for the P4 fill-browser → storage-state handoff,
// used by both the automated test and the demo script.
//
// Flow:
//   1. spawn the audited fill worker (src/audited-filler.mjs) as its own
//      process — optionally as the dedicated slot OS user;
//   2. wait for HANDOFF_READY, run an independent process-tree audit
//      while the fill browser is still open, then close the worker's
//      stdin to release it;
//   3. launch the agent browser with the exported storage-state and
//      prove — from the agent side — that the password is absent from
//      the DOM, storage, and cookies.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { chromium } from 'playwright';

import { auditProcessTree } from './port-audit.mjs';

const WORKER_SCRIPT = fileURLToPath(new URL('./audited-filler.mjs', import.meta.url));

export function spawnFillWorker({ loginUrl, credFile, storageOut, reportOut, switchInfo }) {
  const workerArgs = [
    WORKER_SCRIPT,
    '--login-url',
    loginUrl,
    '--cred-file',
    credFile,
    '--storage-out',
    storageOut,
    '--report-out',
    reportOut,
  ];

  let command = process.execPath;
  let args = workerArgs;
  if (switchInfo.feasible) {
    command = 'sudo';
    args = ['-n', '-u', switchInfo.user, '--', process.execPath, ...workerArgs];
  }

  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });

  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
  });
  child.stderr.on('data', (chunk) => {
    stderr += chunk;
  });

  const ready = new Promise((resolve, reject) => {
    const check = setInterval(() => {
      if (stdout.includes('HANDOFF_READY')) {
        clearInterval(check);
        resolve();
      }
    }, 50);
    child.once('exit', (code) => {
      clearInterval(check);
      reject(new Error(`fill worker exited before HANDOFF_READY (code ${code})\n${stderr}`));
    });
    child.once('error', (error) => {
      clearInterval(check);
      reject(error);
    });
  });

  const exited = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });

  return { child, ready, exited };
}

// Independent audit, run by the parent (not the worker): walk the worker
// process tree, collect browser command lines and listening TCP ports.
export function auditLiveFillWorker(workerPid) {
  return auditProcessTree(workerPid);
}

export function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

export function fileMode(filePath) {
  return (fs.statSync(filePath).mode & 0o777).toString(8).padStart(3, '0');
}

// The agent-side half of the handoff: a browser born with storage-state.
//
// The secret is intentionally NEVER passed into page.evaluate — evaluate
// arguments are serialized into the page, which would plant the very
// value we are proving absent. Comparison happens here, in the driver
// process, against strings returned by the page.
export async function runAgentHandoff({ baseUrl, storageStatePath, secret }) {
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({ storageState: storageStatePath });
    const page = await context.newPage();

    await page.goto(`${baseUrl}/dashboard`);
    const authenticated =
      (await page.locator('#auth-state').getAttribute('data-authenticated')) === 'true';
    const welcomeText = await page.locator('#auth-state').textContent();
    const dashboardHtml = await page.content();
    const dashboardPasswordInDom = dashboardHtml.includes(secret);

    const storageProbe = await page.evaluate(() => ({
      localStorage: JSON.stringify(window.localStorage),
      sessionStorage: JSON.stringify(window.sessionStorage),
    }));

    await page.goto(`${baseUrl}/login`);
    const passwordField = await page.evaluate(() => {
      const field = document.querySelector('input[type="password"]');
      return field ? { present: true, value: field.value } : { present: false, value: null };
    });
    const loginHtml = await page.content();
    const loginPasswordInDom = loginHtml.includes(secret);

    const cookies = await context.cookies();
    const cookiesJson = JSON.stringify(cookies);

    return {
      authenticated,
      welcomeText,
      dashboardPasswordInDom,
      loginPasswordInDom,
      passwordField,
      storageHasSecret:
        storageProbe.localStorage.includes(secret) || storageProbe.sessionStorage.includes(secret),
      cookiesHaveSecret: cookiesJson.includes(secret),
      sessionCookiePresent: cookies.some((cookie) => cookie.name === 'session'),
      cookieNames: cookies.map((cookie) => cookie.name),
    };
  } finally {
    await browser.close();
  }
}

export function makeArtifactPaths(directory) {
  return {
    credFile: path.join(directory, 'fill-credential.json'),
    storageOut: path.join(directory, 'agent-storage-state.json'),
    reportOut: path.join(directory, 'fill-report.json'),
  };
}
