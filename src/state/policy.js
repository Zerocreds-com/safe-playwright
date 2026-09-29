'use strict';

const { canonicalJson } = require('../util/canonical');

/**
 * Deterministic checks for a state mutation (epic #2, C2).
 * Runs before anything touches disk; the LLM advisory layer runs after this
 * and can never substitute for it.
 */

const MUTATION_KINDS = {
  'allowlist.add': { requiresOrigin: true, target: 'allowlist.json' },
  'storage-state.put': { requiresOrigin: true, target: 'storage-state.json' },
  'tool-schema.put': { requiresOrigin: false, target: 'tool-schema.json' },
  'config.put': { requiresOrigin: false, target: 'config.json' },
};

const DEFAULT_LIMITS = {
  minTtlMs: 1_000,
  maxTtlMs: 30 * 24 * 60 * 60 * 1000,
  maxSizeBytes: 64 * 1024,
  intentTtlMs: 60_000,
};

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Normalize an origin string to `scheme://host[:port]`; null if malformed. */
function normalizeOrigin(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  try {
    const url = new URL(value);
    if (url.origin === 'null') return null;
    return url.origin;
  } catch {
    return null;
  }
}

function violation(code, message) {
  return { code, message };
}

/**
 * Deterministic checks, in order: schema → origin ∈ user-intended set →
 * TTL bounds → size bounds. Returns every violation found (not fail-fast on
 * the first one) so a rejected intent gives a complete report.
 *
 * @param {object} mutation
 * @param {object} options
 * @param {Iterable<string>} options.intendedOrigins the user-intended origin set
 * @param {() => number} [options.now]
 * @returns {{ok: boolean, violations: Array<{code: string, message: string}>}}
 */
function checkMutation(mutation, options = {}) {
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const now = typeof options.now === 'function' ? options.now() : Date.now();
  const violations = [];

  // 1. Schema.
  let origin = null;
  if (!isPlainObject(mutation)) {
    violations.push(violation('SCHEMA_INVALID', 'mutation must be a plain object'));
    return { ok: false, violations };
  }
  const kind = mutation.kind;
  const rule = MUTATION_KINDS[kind];
  if (!rule) {
    violations.push(
      violation('SCHEMA_UNKNOWN_KIND', `unknown mutation kind: ${JSON.stringify(kind)}`)
    );
  } else {
    if (rule.requiresOrigin) {
      if (typeof mutation.origin !== 'string') {
        violations.push(violation('SCHEMA_ORIGIN_MISSING', `${kind} requires an origin`));
      } else {
        origin = normalizeOrigin(mutation.origin);
        if (origin === null) {
          violations.push(
            violation('SCHEMA_ORIGIN_MALFORMED', `not a valid origin: ${mutation.origin}`)
          );
        }
      }
    }
    if (mutation.payload !== undefined && !isPlainObject(mutation.payload)) {
      violations.push(violation('SCHEMA_PAYLOAD_INVALID', 'payload must be a plain object'));
    }
    if (!Number.isInteger(mutation.ttlMs)) {
      violations.push(violation('SCHEMA_TTL_INVALID', 'ttlMs must be an integer'));
    }
  }

  // 2. Origin in the user-intended set.
  if (origin !== null) {
    const intended = new Set(
      [...(options.intendedOrigins || [])].map(normalizeOrigin).filter(Boolean)
    );
    if (!intended.has(origin)) {
      violations.push(
        violation('ORIGIN_NOT_INTENDED', `origin ${origin} is not in the user-intended set`)
      );
    }
  }

  // 3. TTL bounds.
  if (Number.isInteger(mutation.ttlMs)) {
    if (mutation.ttlMs < limits.minTtlMs || mutation.ttlMs > limits.maxTtlMs) {
      violations.push(
        violation(
          'TTL_OUT_OF_BOUNDS',
          `ttlMs ${mutation.ttlMs} outside [${limits.minTtlMs}, ${limits.maxTtlMs}]`
        )
      );
    }
  }

  // 4. Size bounds (whole mutation, canonical form).
  const sizeBytes = Buffer.byteLength(canonicalJson(mutation), 'utf8');
  if (sizeBytes > limits.maxSizeBytes) {
    violations.push(
      violation('SIZE_EXCEEDED', `${sizeBytes} bytes > limit ${limits.maxSizeBytes}`)
    );
  }

  return { ok: violations.length === 0, violations };
}

module.exports = { MUTATION_KINDS, DEFAULT_LIMITS, checkMutation, normalizeOrigin, isPlainObject };
