// browser_login backend: the P5 flow behind an MCP call (issue #21).
//
// The credential never enters this process's page or the agent's
// browser: a reference (cred://...) is resolved to a 0600 file, the
// audited fill worker (src/audited-filler.mjs) runs the login in its
// own process over the Playwright pipe, and only the resulting
// storage-state (session cookies) is applied to the agent's context.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { canSwitchUser } from '../slot-user.mjs';
import { spawnFillWorker } from '../handoff-runner.mjs';
import { PolicyError } from './guards.mjs';

const REF_PATTERN = /^cred:\/\/[a-z0-9._-]+(\/[a-z0-9._-]+)*$/i;

function requirePrivateFile(filePath, what) {
  let mode;
  try {
    mode = fs.statSync(filePath).mode & 0o777;
  } catch {
    throw new PolicyError(`${what} not found: ${path.basename(filePath)}`);
  }
  if ((mode & 0o077) !== 0) {
    throw new PolicyError(`${what} must be 0600 (got ${mode.toString(8).padStart(3, '0')})`);
  }
}

export function loadCredentialStore() {
  const storePath = process.env.SAFE_MCP_CRED_STORE;
  if (!storePath) return { entries: new Map() };
  requirePrivateFile(storePath, 'credential store');
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(storePath, 'utf8'));
  } catch {
    throw new PolicyError('credential store is not valid JSON');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new PolicyError('credential store must be an object mapping cred:// refs to entries');
  }
  const entries = new Map(Object.entries(parsed));
  for (const [, entry] of entries) {
    if (!entry || typeof entry.loginUrl !== 'string') {
      throw new PolicyError('credential store entry must provide loginUrl');
    }
    try {
      new URL(entry.loginUrl);
    } catch {
      throw new PolicyError('credential store entry has an invalid loginUrl');
    }
  }
  return { entries };
}

function resolveReference(reference, store) {
  if (typeof reference !== 'string' || !reference.startsWith('cred://')) {
    throw new PolicyError(
      'reference-mode violation: pass a cred:// reference, never a raw secret (C4)',
    );
  }
  if (!REF_PATTERN.test(reference)) {
    throw new PolicyError(`malformed credential reference: ${reference.slice(0, 64)}`);
  }
  const entry = store.entries.get(reference);
  if (!entry) throw new PolicyError(`unknown credential reference: ${reference}`);
  if (typeof entry.credFile !== 'string' || typeof entry.loginUrl !== 'string') {
    throw new PolicyError('credential store entry must provide loginUrl and credFile');
  }
  return entry;
}

// Runs the fill worker, hands the resulting storage-state to the agent
// context, verifies the session, and returns status only.
export async function performLogin(reference, agentContext, store, canaryValues) {
  const entry = resolveReference(reference, store);
  if (canaryValues.some((c) => c.length > 0 && JSON.stringify(entry).includes(c))) {
    throw new PolicyError('credential store entry matches a registered canary — refused');
  }
  requirePrivateFile(entry.credFile, 'credential file');
  if (entry.authUrl) {
    try {
      new URL(entry.authUrl);
    } catch {
      throw new PolicyError('credential store entry has an invalid authUrl');
    }
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'safe-mcp-login-'));
  const storageOut = path.join(tempDir, 'storage-state.json');
  const reportOut = path.join(tempDir, 'fill-report.json');

  try {
    const worker = spawnFillWorker({
      loginUrl: entry.loginUrl,
      credFile: entry.credFile,
      storageOut,
      reportOut,
      switchInfo: canSwitchUser(),
    });
    await worker.ready;
    worker.child.stdin.end();
    const exit = await worker.exited;
    if (exit.code !== 0) {
      throw new PolicyError(`fill worker failed (code ${exit.code}) — see stderr`);
    }

    requirePrivateFile(storageOut, 'storage-state file');
    const state = JSON.parse(fs.readFileSync(storageOut, 'utf8'));
    if (!Array.isArray(state.cookies) || state.cookies.length === 0) {
      throw new PolicyError('fill worker produced no cookies — login did not succeed');
    }
    await agentContext.addCookies(state.cookies);

    let authenticated = null;
    if (entry.authUrl) {
      const response = await agentContext.request.get(entry.authUrl, { timeout: 10_000 });
      const body = await response.json().catch(() => null);
      authenticated = Boolean(body && body.authenticated);
      if (!authenticated) {
        throw new PolicyError('handoff applied but the session did not authenticate');
      }
    }

    // Status only. The result must never contain a credential.
    const result = {
      credentialRef: reference,
      authenticated: authenticated ?? true,
      cookiesApplied: state.cookies.length,
      origins: [...new Set(state.cookies.map((cookie) => cookie.domain))],
      handoff: 'storage-state (P5)',
    };
    const serialized = JSON.stringify(result);
    const leaked = [...store.entries.values()].some((e) => {
      try {
        const cred = JSON.parse(fs.readFileSync(e.credFile, 'utf8'));
        return cred.password && serialized.includes(cred.password);
      } catch {
        return false;
      }
    });
    if (leaked) throw new PolicyError('internal error: result would contain a secret');
    return result;
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}
