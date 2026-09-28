'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { IntentRegistry } = require('./intent');
const { checkMutation, normalizeOrigin, MUTATION_KINDS, DEFAULT_LIMITS } = require('./policy');
const { runAdvisory } = require('./advisory');
const { HashChain, readChainFile, appendChainFile } = require('./chain');

/**
 * Two-phase state mutation pipeline (epic #2, C2), verifier side.
 *
 *   1. `submitIntent(mutation)` — phase one: the daemon asks for permission;
 *      the verifier issues an intent bound to the mutation's hash.
 *   2. `applyIntent(intentId, mutation)` — phase two:
 *      a. intent verification (exists / unexpired / one-shot / same bytes),
 *      b. deterministic checks: origin ∈ user-intended set, schema, TTL,
 *         size bounds,
 *      c. advisory hook (pluggable, never the sole gate),
 *      d. atomic apply to the state file,
 *      e. append to the hash-chained log,
 *      f. notify the attestation verifier (`onApplied`) so it records the
 *         new digest for out-of-band tamper detection.
 *
 * A rejection at any stage leaves disk untouched: nothing is written before
 * step (d), and (d) only runs after (a)–(c) passed.
 */
class StatePipeline {
  constructor({
    storeDir,
    chainPath,
    intendedOrigins = [],
    advisory = null,
    limits = {},
    now,
    onApplied = null,
  } = {}) {
    if (!storeDir) throw new Error('StatePipeline requires storeDir');
    this.storeDir = path.resolve(storeDir);
    this.chainPath = path.resolve(
      chainPath || path.join(this.storeDir, 'state-chain.jsonl')
    );
    this.limits = { ...DEFAULT_LIMITS, ...limits };
    this.now = now || Date.now;
    this.advisory = advisory;
    this.onApplied = onApplied;
    this.intendedOrigins = new Set(
      [...intendedOrigins].map(normalizeOrigin).filter(Boolean)
    );
    this.registry = new IntentRegistry({ now: this.now, ttlMs: this.limits.intentTtlMs });
    this.chain = new HashChain({
      entries: readChainFile(this.chainPath),
      now: () => new Date(this.now()).toISOString(),
    });
    fs.mkdirSync(this.storeDir, { recursive: true });
  }

  /** Seed/extend the set of origins the user actually intended. */
  addIntendedOrigin(origin) {
    const normalized = normalizeOrigin(origin);
    if (!normalized) throw new Error(`not a valid origin: ${origin}`);
    this.intendedOrigins.add(normalized);
    return normalized;
  }

  /** Phase 1: submit the mutation, get an intent back. */
  submitIntent(mutation) {
    return this.registry.submit(mutation);
  }

  /** Phase 2: verify intent → deterministic checks → advisory → apply → log. */
  async applyIntent(intentId, mutation) {
    const intentCheck = this.registry.consume(intentId, mutation);
    if (!intentCheck.ok) {
      return { applied: false, stage: 'intent', code: intentCheck.code };
    }

    const checks = checkMutation(mutation, {
      intendedOrigins: this.intendedOrigins,
      now: this.now,
      limits: this.limits,
    });
    if (!checks.ok) {
      return {
        applied: false,
        stage: 'checks',
        code: 'DETERMINISTIC_VIOLATION',
        violations: checks.violations,
      };
    }

    const advisory = await runAdvisory(this.advisory, {
      intent: intentCheck.intent,
      mutation,
      checks,
    });
    if (advisory.verdict === 'reject') {
      return {
        applied: false,
        stage: 'advisory',
        code: 'ADVISORY_REJECT',
        reason: advisory.reason,
      };
    }

    let target;
    try {
      target = this.applyToFile(intentCheck.intent, mutation);
    } catch (err) {
      return { applied: false, stage: 'apply', code: 'APPLY_FAILED', reason: err.message };
    }

    const entry = this.chain.append({
      kind: mutation.kind,
      intentId: intentCheck.intent.id,
      mutationHash: intentCheck.intent.mutationHash,
      origin: normalizeOrigin(mutation.origin),
      path: path.relative(this.storeDir, target),
    });
    appendChainFile(this.chainPath, entry);

    if (this.onApplied) this.onApplied(target, entry);

    return {
      applied: true,
      stage: 'applied',
      path: target,
      intentId: intentCheck.intent.id,
      seq: entry.seq,
      entryHash: entry.hash,
      advisoryVerdict: advisory.verdict,
    };
  }

  verifyChain() {
    return HashChain.verify(readChainFile(this.chainPath));
  }

  targetPath(mutation) {
    const rule = MUTATION_KINDS[mutation.kind];
    if (!rule) throw new Error(`unknown mutation kind: ${mutation.kind}`);
    return path.join(this.storeDir, rule.target);
  }

  applyToFile(intent, mutation) {
    const target = this.targetPath(mutation);
    const nowIso = new Date(this.now()).toISOString();

    if (mutation.kind === 'allowlist.add') {
      const doc = readJson(target, { entries: [] });
      const origin = normalizeOrigin(mutation.origin);
      const entry = {
        origin,
        ttlMs: mutation.ttlMs,
        expiresAt: new Date(this.now() + mutation.ttlMs).toISOString(),
        appliedAt: nowIso,
        intentId: intent.id,
      };
      if (mutation.label !== undefined) entry.label = mutation.label;
      const existing = doc.entries.findIndex((item) => item && item.origin === origin);
      if (existing >= 0) doc.entries[existing] = entry;
      else doc.entries.push(entry);
      doc.updatedAt = nowIso;
      writeJsonAtomic(target, doc);
      return target;
    }

    const doc = readJson(target, { data: {} });
    doc.data = { ...doc.data, ...(mutation.payload || {}) };
    doc.updatedAt = nowIso;
    doc.intentId = intent.id;
    writeJsonAtomic(target, doc);
    return target;
  }
}

function readJson(filePath, fallback) {
  if (!fs.existsSync(filePath)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    throw new Error(`state file is unreadable, refusing to apply: ${err.message}`);
  }
}

function writeJsonAtomic(filePath, value) {
  const tmp = `${filePath}.${process.pid}.${Math.random().toString(16).slice(2)}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n');
  fs.renameSync(tmp, filePath);
}

module.exports = { StatePipeline, writeJsonAtomic };
