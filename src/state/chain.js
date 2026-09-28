'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256Hex } = require('../util/canonical');

const GENESIS_HASH = '0'.repeat(64);

function entryHash({ seq, ts, prevHash, payload }) {
  return sha256Hex(canonicalJson({ seq, ts, prevHash, payload }));
}

/**
 * Hash-chained state-change log (epic #2, C14 shape, P2 scope).
 * Every entry commits to its content and to the previous entry's hash, so
 * editing or deleting any historical line is detectable by a full re-verify.
 */
class HashChain {
  constructor({ entries = [], now } = {}) {
    this._entries = entries.slice();
    this.now = now || (() => new Date().toISOString());
  }

  get entries() {
    return this._entries.slice();
  }

  append(payload) {
    const prev = this._entries.length > 0
      ? this._entries[this._entries.length - 1].hash
      : GENESIS_HASH;
    const entry = {
      seq: this._entries.length + 1,
      ts: this.now(),
      prevHash: prev,
      payload,
    };
    entry.hash = entryHash(entry);
    this._entries.push(entry);
    return entry;
  }

  verify() {
    return HashChain.verify(this._entries);
  }

  static verify(entries) {
    let prev = GENESIS_HASH;
    for (let i = 0; i < entries.length; i += 1) {
      const entry = entries[i];
      if (!entry || typeof entry !== 'object') {
        return { ok: false, brokenAt: i + 1, reason: 'malformed-entry' };
      }
      if (entry.seq !== i + 1) {
        return { ok: false, brokenAt: entry.seq, reason: 'sequence' };
      }
      if (entry.prevHash !== prev) {
        return { ok: false, brokenAt: entry.seq, reason: 'prev-hash' };
      }
      if (entry.hash !== entryHash(entry)) {
        return { ok: false, brokenAt: entry.seq, reason: 'content-hash' };
      }
      prev = entry.hash;
    }
    return { ok: true, brokenAt: null, reason: null, count: entries.length };
  }
}

function readChainFile(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const lines = fs.readFileSync(filePath, 'utf8').split('\n').filter((line) => line.trim() !== '');
  return lines.map((line) => JSON.parse(line));
}

function appendChainFile(filePath, entry) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, JSON.stringify(entry) + '\n');
  return entry;
}

module.exports = { GENESIS_HASH, HashChain, entryHash, readChainFile, appendChainFile };
