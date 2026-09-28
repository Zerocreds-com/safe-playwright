'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');

/**
 * Deterministic JSON: object keys sorted recursively, no whitespace.
 * Everything that is hashed (manifests, mutations, chain entries) goes
 * through this so hashes are stable across processes and runs.
 */
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJson).join(',') + ']';
  }
  const keys = Object.keys(value)
    .filter((key) => value[key] !== undefined)
    .sort();
  return '{' + keys.map((key) => JSON.stringify(key) + ':' + canonicalJson(value[key])).join(',') + '}';
}

function sha256Hex(input) {
  const hash = crypto.createHash('sha256');
  hash.update(typeof input === 'string' ? Buffer.from(input, 'utf8') : input);
  return hash.digest('hex');
}

function hashFile(filePath) {
  return sha256Hex(fs.readFileSync(filePath));
}

module.exports = { canonicalJson, sha256Hex, hashFile };
