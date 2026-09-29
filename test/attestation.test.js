'use strict';

const { test, describe, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  cleanupTempDirs,
  createVerifierFixture,
  createPipeline,
  allowlistMutation,
} = require('./helpers');
const { verifyManifestSignature } = require('../src/attestation/manifest');
const { Verifier } = require('../src/attestation/verifier');

after(cleanupTempDirs);

describe('spawn-time attestation against the signed manifest', () => {
  test('clean tree passes and raises no alert', () => {
    const fixture = createVerifierFixture();
    const result = fixture.verifier.spawnCheck();
    assert.equal(result.ok, true);
    assert.deepEqual(result.mismatches, []);
    assert.equal(fixture.alerts.length, 0);
  });

  test('binary tamper fails the spawn check and is alerted', () => {
    const fixture = createVerifierFixture();
    fs.writeFileSync(path.join(fixture.root, 'bin', 'driver.bin'), 'TAMPERED\n');

    const result = fixture.verifier.spawnCheck();

    assert.equal(result.ok, false);
    assert.equal(result.stage, 'spawn');
    assert.equal(result.mismatches[0].path, 'bin/driver.bin');
    assert.equal(result.mismatches[0].reason, 'hash-mismatch');

    assert.equal(fixture.alerts.length, 1);
    assert.equal(fixture.alerts[0].kind, 'attestation.mismatch');
    assert.equal(fixture.alerts[0].emitter, 'verifier');
    assert.equal(fixture.alerts[0].detail.stage, 'spawn');
  });

  test('a forged manifest signature is rejected before any file check', () => {
    const fixture = createVerifierFixture();
    const forged = {
      manifest: { ...fixture.signedManifest.manifest },
      signature: Buffer.from('not-a-real-signature').toString('base64'),
    };

    const signature = verifyManifestSignature(forged, fixture.keys.publicKeyPem);
    assert.equal(signature.ok, false);

    const forgedVerifier = new Verifier({
      rootDir: fixture.root,
      signedManifest: forged,
      publicKeyPem: fixture.keys.publicKeyPem,
      alertChannel: fixture.alertChannel,
    });
    const result = forgedVerifier.spawnCheck();

    assert.equal(result.ok, false);
    assert.equal(result.stage, 'spawn');
    assert.equal(fixture.alerts.length, 1);
    assert.equal(fixture.alerts[0].kind, 'attestation.manifest-invalid');
    assert.equal(fixture.alerts[0].emitter, 'verifier');
  });
});

describe('periodic re-hash', () => {
  test('binary tamper is detected at the next re-hash cycle (issue #3 AC2)', () => {
    const fixture = createVerifierFixture();
    assert.equal(fixture.verifier.spawnCheck().ok, true);

    fs.writeFileSync(path.join(fixture.root, 'bin', 'driver.bin'), 'ROOTKIT\n');

    const report = fixture.verifier.rehashCycle();

    assert.equal(report.ok, false);
    assert.equal(report.issues.length, 1);
    assert.equal(report.issues[0].class, 'code');
    assert.equal(report.issues[0].path, 'bin/driver.bin');

    assert.equal(fixture.alerts.length, 1);
    assert.equal(fixture.alerts[0].kind, 'attestation.mismatch');
    assert.equal(fixture.alerts[0].emitter, 'verifier');
    assert.equal(fixture.alerts[0].detail.stage, 'rehash');
    assert.ok(fixture.alerts[0].detail.classes.includes('code'));

    const onDisk = fs
      .readFileSync(fixture.alertPath, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    assert.equal(onDisk.length, 1);
    assert.equal(onDisk[0].emitter, 'verifier');
  });

  test('a second cycle is clean again once nothing changed', () => {
    const fixture = createVerifierFixture();
    assert.equal(fixture.verifier.spawnCheck().ok, true);
    assert.equal(fixture.verifier.rehashCycle().ok, true);
    assert.equal(fixture.alerts.length, 0);
  });

  test('out-of-band allowlist.json tamper is detected and alerted (issue #3 AC1)', async () => {
    const fixture = createVerifierFixture();
    assert.equal(fixture.verifier.spawnCheck().ok, true);

    const pipeline = createPipeline({ fixture });
    const mutation = allowlistMutation();
    const intent = pipeline.submitIntent(mutation);
    const result = await pipeline.applyIntent(intent.id, mutation);
    assert.equal(result.applied, true);

    const allowlistPath = path.join(fixture.storeDir, 'allowlist.json');
    assert.equal(fixture.verifier.rehashCycle().ok, true);

    // Out-of-band edit: no intent, no pipeline, no daemon involvement.
    fs.writeFileSync(
      allowlistPath,
      JSON.stringify({ entries: [{ origin: 'https://evil.example' }] })
    );

    const report = fixture.verifier.rehashCycle();

    assert.equal(report.ok, false);
    assert.equal(report.issues.length, 1);
    assert.equal(report.issues[0].class, 'state');
    assert.equal(report.issues[0].path, allowlistPath);

    assert.equal(fixture.alerts.length, 1);
    assert.equal(fixture.alerts[0].kind, 'attestation.mismatch');
    assert.equal(fixture.alerts[0].emitter, 'verifier');
    assert.ok(fixture.alerts[0].detail.classes.includes('state'));
    assert.ok(fixture.alerts[0].detail.issues[0].path.endsWith('allowlist.json'));
  });

  test('a deleted state file is reported, not silently ignored', async () => {
    const fixture = createVerifierFixture();
    const pipeline = createPipeline({ fixture });
    const mutation = allowlistMutation();
    const intent = pipeline.submitIntent(mutation);
    await pipeline.applyIntent(intent.id, mutation);

    fs.rmSync(path.join(fixture.storeDir, 'allowlist.json'));

    const report = fixture.verifier.rehashCycle();
    assert.equal(report.ok, false);
    assert.equal(report.issues[0].reason, 'missing');
    assert.equal(fixture.alerts.length, 1);
  });
});
