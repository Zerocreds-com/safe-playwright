'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, hashFile } = require('../util/canonical');

const MANIFEST_SCHEMA = 'safe-playwright.signed-manifest/v1';

/** Generate an Ed25519 key pair for manifest signing (PEM strings). */
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

function normalizeRelPath(relPath) {
  return String(relPath).replace(/\\/g, '/').replace(/^\.\//, '');
}

/**
 * Build a manifest for `files` (paths relative to `rootDir`) by hashing them.
 * The manifest is an inventory of the audited driver/deps/state entry points.
 */
function buildManifest({ rootDir, files, createdAt }) {
  const entries = files.map((relPath) => {
    const normalized = normalizeRelPath(relPath);
    return { path: normalized, sha256: hashFile(path.join(rootDir, normalized)) };
  });
  return {
    schema: MANIFEST_SCHEMA,
    createdAt: createdAt || new Date().toISOString(),
    files: entries,
  };
}

/** Detached Ed25519 signature over the canonical form of the manifest. */
function signManifest(manifest, privateKeyPem) {
  const data = Buffer.from(canonicalJson(manifest), 'utf8');
  const signature = crypto.sign(null, data, privateKeyPem);
  return { manifest, signature: signature.toString('base64') };
}

function verifyManifestSignature(signedManifest, publicKeyPem) {
  if (!signedManifest || typeof signedManifest !== 'object') {
    return { ok: false, reason: 'malformed' };
  }
  if (!signedManifest.manifest || !signedManifest.signature) {
    return { ok: false, reason: 'malformed' };
  }
  if (signedManifest.manifest.schema !== MANIFEST_SCHEMA) {
    return { ok: false, reason: 'schema' };
  }
  if (!Array.isArray(signedManifest.manifest.files)) {
    return { ok: false, reason: 'files' };
  }
  const data = Buffer.from(canonicalJson(signedManifest.manifest), 'utf8');
  let ok = false;
  try {
    ok = crypto.verify(
      null,
      data,
      publicKeyPem,
      Buffer.from(signedManifest.signature, 'base64')
    );
  } catch {
    ok = false;
  }
  return ok ? { ok: true } : { ok: false, reason: 'signature-mismatch' };
}

/**
 * Hash every file listed in the manifest and compare against the recorded
 * digests. A missing file counts as a mismatch (`reason: 'missing'`).
 */
function checkManifestFiles(manifest, rootDir) {
  const mismatches = [];
  for (const entry of manifest.files) {
    const filePath = path.join(rootDir, entry.path);
    let actual = null;
    try {
      actual = hashFile(filePath);
    } catch {
      actual = null;
    }
    if (actual !== entry.sha256) {
      mismatches.push({
        path: entry.path,
        expected: entry.sha256,
        actual,
        reason: actual === null ? 'missing' : 'hash-mismatch',
      });
    }
  }
  return { ok: mismatches.length === 0, mismatches };
}

module.exports = {
  MANIFEST_SCHEMA,
  generateKeyPair,
  buildManifest,
  signManifest,
  verifyManifestSignature,
  checkManifestFiles,
};
