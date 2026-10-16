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
import crypto from 'node:crypto';

import { canSwitchUser } from '../slot-user.mjs';
import { spawnFillWorker } from '../handoff-runner.mjs';
import { PolicyError } from './guards.mjs';

const REF_PATTERN = /^cred:\/\/[a-z0-9._-]+(\/[a-z0-9._-]+)*$/i;
const ZEROCREDS_REF_PATTERN = /^zerocreds:\/\/([a-z0-9_-]{1,64})\/([a-z0-9_-]{1,64})$/i;

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

function readZeroCredsToken() {
  const tokenPath = process.env.SAFE_MCP_ZEROCREDS_ADMIN_TOKEN_FILE;
  if (!tokenPath) throw new PolicyError('ZeroCreds broker token file is not configured');
  let fd;
  try {
    fd = fs.openSync(tokenPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || (stat.mode & 0o077) !== 0
        || (process.getuid && stat.uid !== process.getuid()) || stat.size > 256) {
      throw new PolicyError('ZeroCreds broker token file must be private and owned by this user');
    }
    const token = fs.readFileSync(fd, 'utf8').trim();
    if (token.length < 32 || /\s/.test(token)) throw new PolicyError('ZeroCreds broker token file is invalid');
    return token;
  } catch (error) {
    if (error instanceof PolicyError) throw error;
    throw new PolicyError('ZeroCreds broker token file is unavailable');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

async function requestZeroCredsGrant(reference) {
  const match = reference.match(ZEROCREDS_REF_PATTERN);
  if (!match) throw new PolicyError('malformed ZeroCreds reference');
  let base;
  try { base = new URL(process.env.SAFE_MCP_ZEROCREDS_URL || ''); } catch {
    throw new PolicyError('ZeroCreds broker URL is not configured');
  }
  if (base.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname)
      || base.username || base.password || base.pathname !== '/' || base.search || base.hash) {
    throw new PolicyError('ZeroCreds broker must use a loopback URL');
  }
  const token = readZeroCredsToken();
  const runId = crypto.randomUUID();
  let response;
  try {
    response = await fetch(new URL('/api/local/broker/grants', base), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ provider: match[1].toLowerCase(), account_alias: match[2].toLowerCase(), run_id: runId }),
      redirect: 'error',
      signal: AbortSignal.timeout(8000),
    });
  } catch {
    throw new PolicyError('ZeroCreds broker unavailable');
  }
  if (!response.ok) throw new PolicyError('ZeroCreds refused the browser login grant');
  let data;
  try {
    const raw = await response.text();
    if (Buffer.byteLength(raw) > 16_384) throw new Error('oversized');
    data = JSON.parse(raw);
  } catch { throw new PolicyError('ZeroCreds returned invalid grant metadata'); }
  const approved = data?.approved_origin;
  let login;
  let auth = null;
  let brokerEndpoint;
  try {
    login = new URL(data.login_url);
    if (data.auth_url) auth = new URL(data.auth_url);
    brokerEndpoint = new URL(data.broker_url);
  } catch { throw new PolicyError('ZeroCreds returned invalid login policy'); }
  let approvedHost = '';
  try {
    const approvedUrl = new URL(approved);
    if (approvedUrl.origin !== approved) throw new Error('origin only');
    approvedHost = approvedUrl.hostname.replace(/^\[|\]$/g, '');
  } catch { throw new PolicyError('ZeroCreds returned invalid login policy'); }
  const approvedLoopbackHttp = login.protocol === 'http:' && ['127.0.0.1', 'localhost', '::1'].includes(approvedHost);
  const expiresAt = Date.parse(data?.expires_at);
  if (typeof data.grant !== 'string' || !/^[a-f0-9]{64}$/.test(data.grant)
      || brokerEndpoint.origin !== base.origin || brokerEndpoint.pathname !== '/api/local/broker/redeem'
      || brokerEndpoint.username || brokerEndpoint.password
      || data.run_id !== runId || data.provider !== match[1].toLowerCase()
      || data.account_alias !== match[2].toLowerCase()
      || !Number.isFinite(expiresAt) || expiresAt <= Date.now() || expiresAt > Date.now() + 60_000
      || (login.protocol !== 'https:' && !approvedLoopbackHttp) || login.origin !== approved
      || (auth && ((auth.protocol !== 'https:' && !(approvedLoopbackHttp && auth.protocol === 'http:')) || auth.origin !== approved))
      || typeof data.username_selector !== 'string' || typeof data.password_selector !== 'string'
      || data.username_selector === data.password_selector
      || typeof data.submit_selector !== 'string' || typeof data.success_selector !== 'string') {
    throw new PolicyError('ZeroCreds returned invalid login policy');
  }
  return {
    grant: data.grant,
    brokerUrl: data.broker_url,
    approvedOrigin: approved,
    entry: {
      loginUrl: login.href,
      authUrl: auth?.href || null,
      usernameSelector: data.username_selector,
      passwordSelector: data.password_selector,
      submitSelector: data.submit_selector,
      successSelector: data.success_selector,
    },
  };
}

// Runs the fill worker, hands the resulting storage-state to the agent
// context, verifies the session, and returns status only.
export async function performLogin(reference, agentContext, store, canaryValues) {
  const brokerMode = reference.startsWith('zerocreds://');
  const broker = brokerMode ? await requestZeroCredsGrant(reference) : null;
  const entry = broker ? broker.entry : resolveReference(reference, store);
  if (canaryValues.some((c) => c.length > 0 && JSON.stringify(entry).includes(c))) {
    throw new PolicyError('credential store entry matches a registered canary — refused');
  }
  if (!brokerMode) requirePrivateFile(entry.credFile, 'credential file');
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
      ...(broker ? {
        brokerUrl: broker.brokerUrl,
        brokerGrant: broker.grant,
        approvedOrigin: broker.approvedOrigin,
        usernameSelector: entry.usernameSelector,
        passwordSelector: entry.passwordSelector,
        submitSelector: entry.submitSelector,
        successSelector: entry.successSelector,
      } : { credFile: entry.credFile }),
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
    const leaked = !brokerMode && [...store.entries.values()].some((e) => {
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
