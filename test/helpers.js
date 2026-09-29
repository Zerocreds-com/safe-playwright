'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { generateKeyPair, buildManifest, signManifest } = require('../src/attestation/manifest');
const { AlertChannel } = require('../src/attestation/alert-channel');
const { Verifier } = require('../src/attestation/verifier');
const { StatePipeline } = require('../src/state/pipeline');

const tempDirs = [];

function tempDir(prefix = 'safe-playwright-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function cleanupTempDirs() {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const MANAGED_FILES = ['bin/driver.bin', 'deps/lock.json'];

/**
 * A verifier fixture: a fake audited root (binary + dep lock), a signed
 * manifest, an alert channel with an in-memory capture, and the verifier.
 */
function createVerifierFixture() {
  const dir = tempDir();
  const root = path.join(dir, 'root');
  fs.mkdirSync(path.join(root, 'bin'), { recursive: true });
  fs.mkdirSync(path.join(root, 'deps'), { recursive: true });
  fs.writeFileSync(path.join(root, 'bin', 'driver.bin'), 'DRIVER-BINARY-v1\n');
  fs.writeFileSync(path.join(root, 'deps', 'lock.json'), '{"lockfileVersion":1,"deps":{}}\n');

  const keys = generateKeyPair();
  const manifest = buildManifest({ rootDir: root, files: MANAGED_FILES });
  const signedManifest = signManifest(manifest, keys.privateKeyPem);

  const alerts = [];
  const alertPath = path.join(dir, 'alerts.jsonl');
  const alertChannel = new AlertChannel({ filePath: alertPath, emitter: 'verifier' });
  alertChannel.onAlert((alert) => alerts.push(alert));

  const verifier = new Verifier({
    rootDir: root,
    signedManifest,
    publicKeyPem: keys.publicKeyPem,
    alertChannel,
  });

  return {
    dir,
    root,
    keys,
    manifest,
    signedManifest,
    alertPath,
    alertChannel,
    alerts,
    verifier,
    storeDir: path.join(dir, 'state'),
  };
}

function createPipeline({ fixture, intendedOrigins = ['https://example.com'], ...rest } = {}) {
  return new StatePipeline({
    storeDir: fixture ? fixture.storeDir : tempDir(),
    intendedOrigins,
    ...(fixture ? { onApplied: (target) => fixture.verifier.recordState(target) } : {}),
    ...rest,
  });
}

function allowlistMutation(overrides = {}) {
  return {
    kind: 'allowlist.add',
    origin: 'https://example.com',
    ttlMs: 60_000,
    label: 'test-origin',
    ...overrides,
  };
}

module.exports = {
  tempDir,
  cleanupTempDirs,
  createVerifierFixture,
  createPipeline,
  allowlistMutation,
  MANAGED_FILES,
};
