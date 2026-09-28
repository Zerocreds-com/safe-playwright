'use strict';

const path = require('node:path');
const { hashFile } = require('../util/canonical');
const {
  verifyManifestSignature,
  checkManifestFiles,
} = require('./manifest');

/**
 * External attestation verifier — a component that lives *outside* the
 * daemon (epic #2, C1/C3).
 *
 * Responsibilities:
 *  - spawn-time check: manifest signature + every listed file re-hashed
 *    against the signed manifest, before the daemon is allowed to run;
 *  - periodic re-hash: code/deps (from the manifest) *and* state files
 *    registered via `recordState()` after each verified mutation;
 *  - alerts: every mismatch is pushed through the verifier-owned
 *    `AlertChannel`. The daemon has no access to this channel, so killing or
 *    subverting the daemon cannot suppress the alert (A5).
 */
class Verifier {
  constructor({ rootDir, signedManifest, publicKeyPem, alertChannel }) {
    if (!rootDir) throw new Error('Verifier requires rootDir');
    if (!signedManifest) throw new Error('Verifier requires signedManifest');
    if (!publicKeyPem) throw new Error('Verifier requires publicKeyPem');
    if (!alertChannel) throw new Error('Verifier requires a verifier-owned alertChannel');
    this.rootDir = path.resolve(rootDir);
    this.signedManifest = signedManifest;
    this.publicKeyPem = publicKeyPem;
    this.alertChannel = alertChannel;
    this.codeFiles = new Map(
      (signedManifest.manifest.files || []).map((entry) => [entry.path, entry.sha256])
    );
    this.stateFiles = new Map();
    this.timer = null;
  }

  /** Spawn-time check: signature first, then file digests. */
  spawnCheck() {
    const signature = verifyManifestSignature(this.signedManifest, this.publicKeyPem);
    if (!signature.ok) {
      this.alertChannel.emit('attestation.manifest-invalid', {
        stage: 'spawn',
        reason: signature.reason,
      });
      return { ok: false, stage: 'spawn', reason: signature.reason, mismatches: [] };
    }
    const report = checkManifestFiles(this.signedManifest.manifest, this.rootDir);
    if (!report.ok) {
      this.alertChannel.emit('attestation.mismatch', {
        stage: 'spawn',
        class: 'code',
        mismatches: report.mismatches,
      });
    }
    return { ok: report.ok, stage: 'spawn', class: 'code', mismatches: report.mismatches };
  }

  /**
   * Register the current digest of a state file that was written through the
   * verified intent pipeline. Later out-of-band edits show up as a re-hash
   * mismatch on this path.
   */
  recordState(filePath) {
    const resolved = path.resolve(filePath);
    this.stateFiles.set(resolved, hashFile(resolved));
    return resolved;
  }

  forgetState(filePath) {
    this.stateFiles.delete(path.resolve(filePath));
  }

  /** One re-hash cycle over code (manifest) + registered state files. */
  rehashCycle() {
    const issues = [];

    for (const [relPath, expected] of this.codeFiles) {
      let actual = null;
      try {
        actual = hashFile(path.join(this.rootDir, relPath));
      } catch {
        actual = null;
      }
      if (actual !== expected) {
        issues.push({
          class: 'code',
          path: relPath,
          expected,
          actual,
          reason: actual === null ? 'missing' : 'hash-mismatch',
        });
      }
    }

    for (const [absPath, expected] of this.stateFiles) {
      let actual = null;
      try {
        actual = hashFile(absPath);
      } catch {
        actual = null;
      }
      if (actual !== expected) {
        issues.push({
          class: 'state',
          path: absPath,
          expected,
          actual,
          reason: actual === null ? 'missing' : 'hash-mismatch',
        });
      }
    }

    if (issues.length > 0) {
      this.alertChannel.emit('attestation.mismatch', {
        stage: 'rehash',
        classes: [...new Set(issues.map((issue) => issue.class))],
        issues,
      });
    }
    return { ok: issues.length === 0, issues };
  }

  startRehash(intervalMs) {
    this.stopRehash();
    if (!Number.isFinite(intervalMs) || intervalMs <= 0) {
      throw new Error('startRehash requires a positive intervalMs');
    }
    this.timer = setInterval(() => this.rehashCycle(), intervalMs);
    if (typeof this.timer.unref === 'function') this.timer.unref();
    return this;
  }

  stopRehash() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    return this;
  }
}

module.exports = { Verifier };
