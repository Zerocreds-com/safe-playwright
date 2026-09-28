'use strict';

/**
 * Advisory hook — pluggable, LLM or otherwise (epic #2, C2 step 3).
 *
 * Interface:
 *
 *   hook = {
 *     check(context) -> { verdict: 'allow' | 'reject' | 'abstain', reason?: string }
 *                        | Promise<same>
 *   }
 *
 * `context` = { intent, mutation, checks } where `checks` is the result of
 * the deterministic policy pass.
 *
 * Contract — the advisory layer is NEVER the sole gate:
 *  - deterministic checks run first and their failure is final; a hook
 *    returning `allow` cannot resurrect a rejected mutation;
 *  - `reject` from the hook is a veto on top of the deterministic checks;
 *  - a hook that throws, times out or returns a malformed verdict is
 *    treated as `reject` (fail closed);
 *  - no hook configured → `abstain`, deterministic checks decide alone.
 *
 * No live LLM call ships with this interface — wiring one up is a matter of
 * supplying an object with a `check` method.
 */

async function runAdvisory(hook, context) {
  if (!hook || typeof hook.check !== 'function') {
    return { verdict: 'abstain', reason: 'no-advisory-hook' };
  }
  try {
    const raw = await hook.check(context);
    const verdict = raw && typeof raw === 'object' ? raw.verdict : raw;
    if (verdict === 'allow' || verdict === 'reject' || verdict === 'abstain') {
      return { verdict, reason: (raw && raw.reason) || '' };
    }
    return { verdict: 'reject', reason: 'advisory returned a malformed verdict' };
  } catch (err) {
    return { verdict: 'reject', reason: `advisory-error: ${err.message}` };
  }
}

module.exports = { runAdvisory };
