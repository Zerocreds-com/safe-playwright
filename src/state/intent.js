'use strict';

const { randomUUID } = require('node:crypto');
const { canonicalJson, sha256Hex } = require('../util/canonical');

/**
 * Intent registry — the first phase of the two-phase state pipeline.
 *
 * A mutation is never applied directly. The client first submits it and
 * receives an intent (an opaque id bound to the mutation's hash). `consume`
 * is the only way to unlock an apply, and it enforces:
 *  - the intent exists,
 *  - it has not expired,
 *  - it has not been used already (one-shot; marked consumed on first
 *    successful verification, even if a later check rejects the mutation),
 *  - the mutation being applied is byte-for-byte the one the intent covers.
 */
class IntentRegistry {
  constructor({ now, ttlMs = 60_000 } = {}) {
    this.now = now || Date.now;
    this.ttlMs = ttlMs;
    this.intents = new Map();
  }

  submit(mutation) {
    const createdAt = this.now();
    const id = randomUUID();
    const intent = {
      id,
      mutationHash: sha256Hex(canonicalJson(mutation)),
      createdAt,
      expiresAt: createdAt + this.ttlMs,
      consumed: false,
    };
    this.intents.set(id, intent);
    return {
      id: intent.id,
      mutationHash: intent.mutationHash,
      createdAt,
      expiresAt: intent.expiresAt,
    };
  }

  consume(intentId, mutation) {
    const intent = this.intents.get(intentId);
    if (!intent) {
      return { ok: false, code: 'INTENT_NOT_FOUND' };
    }
    if (intent.consumed) {
      return { ok: false, code: 'INTENT_ALREADY_USED' };
    }
    if (this.now() > intent.expiresAt) {
      return { ok: false, code: 'INTENT_EXPIRED' };
    }
    const actualHash = sha256Hex(canonicalJson(mutation));
    if (actualHash !== intent.mutationHash) {
      return { ok: false, code: 'INTENT_MUTATION_MISMATCH' };
    }
    intent.consumed = true;
    return { ok: true, intent };
  }
}

module.exports = { IntentRegistry };
