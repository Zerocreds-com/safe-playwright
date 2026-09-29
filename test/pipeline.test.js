'use strict';

const { test, describe, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');

const { cleanupTempDirs, tempDir, allowlistMutation } = require('./helpers');
const { StatePipeline } = require('../src/state/pipeline');
const { DEFAULT_LIMITS } = require('../src/state/policy');

after(cleanupTempDirs);

function pipelineFixture(options = {}) {
  const storeDir = tempDir();
  const pipeline = new StatePipeline({
    storeDir,
    intendedOrigins: ['https://example.com', 'https://app.example.com'],
    ...options,
  });
  return { storeDir, pipeline, allowlistPath: path.join(storeDir, 'allowlist.json') };
}

describe('two-phase pipeline: intent verification', () => {
  test('a mutation without a verified intent never reaches disk (issue #3 AC4)', async () => {
    const { pipeline, allowlistPath } = pipelineFixture();

    const result = await pipeline.applyIntent(randomUUID(), allowlistMutation());

    assert.equal(result.applied, false);
    assert.equal(result.stage, 'intent');
    assert.equal(result.code, 'INTENT_NOT_FOUND');
    assert.equal(fs.existsSync(allowlistPath), false);
    assert.deepEqual(fs.readdirSync(path.dirname(allowlistPath)), []);
  });

  test('an intent issued for a different mutation is refused', async () => {
    const { pipeline, allowlistPath } = pipelineFixture();
    const intent = pipeline.submitIntent(allowlistMutation());

    const result = await pipeline.applyIntent(
      intent.id,
      allowlistMutation({ origin: 'https://evil.example' })
    );

    assert.equal(result.applied, false);
    assert.equal(result.code, 'INTENT_MUTATION_MISMATCH');
    assert.equal(fs.existsSync(allowlistPath), false);
  });

  test('an intent is single-use', async () => {
    const { pipeline } = pipelineFixture();
    const mutation = allowlistMutation();
    const intent = pipeline.submitIntent(mutation);

    const first = await pipeline.applyIntent(intent.id, mutation);
    assert.equal(first.applied, true);

    const second = await pipeline.applyIntent(intent.id, mutation);
    assert.equal(second.applied, false);
    assert.equal(second.code, 'INTENT_ALREADY_USED');
  });

  test('an expired intent is refused', async () => {
    let clock = 1_700_000_000_000;
    const { pipeline, allowlistPath } = pipelineFixture({ now: () => clock });
    const mutation = allowlistMutation();
    const intent = pipeline.submitIntent(mutation);

    clock += DEFAULT_LIMITS.intentTtlMs + 1;

    const result = await pipeline.applyIntent(intent.id, mutation);
    assert.equal(result.applied, false);
    assert.equal(result.code, 'INTENT_EXPIRED');
    assert.equal(fs.existsSync(allowlistPath), false);
  });
});

describe('two-phase pipeline: deterministic checks', () => {
  test('origin outside the user-intended set is rejected', async () => {
    const { pipeline, allowlistPath } = pipelineFixture();
    const mutation = allowlistMutation({ origin: 'https://not-intended.example' });
    const intent = pipeline.submitIntent(mutation);

    const result = await pipeline.applyIntent(intent.id, mutation);

    assert.equal(result.applied, false);
    assert.equal(result.stage, 'checks');
    assert.ok(result.violations.some((v) => v.code === 'ORIGIN_NOT_INTENDED'));
    assert.equal(fs.existsSync(allowlistPath), false);
  });

  test('schema violations are rejected', async () => {
    const { pipeline, allowlistPath } = pipelineFixture();

    const unknownKind = allowlistMutation({ kind: 'allowlist.nuke' });
    const intentA = pipeline.submitIntent(unknownKind);
    const resultA = await pipeline.applyIntent(intentA.id, unknownKind);
    assert.equal(resultA.stage, 'checks');
    assert.ok(resultA.violations.some((v) => v.code === 'SCHEMA_UNKNOWN_KIND'));

    const missingOrigin = allowlistMutation();
    delete missingOrigin.origin;
    const intentB = pipeline.submitIntent(missingOrigin);
    const resultB = await pipeline.applyIntent(intentB.id, missingOrigin);
    assert.ok(resultB.violations.some((v) => v.code === 'SCHEMA_ORIGIN_MISSING'));

    const badTtl = allowlistMutation({ ttlMs: 'soon' });
    const intentC = pipeline.submitIntent(badTtl);
    const resultC = await pipeline.applyIntent(intentC.id, badTtl);
    assert.ok(resultC.violations.some((v) => v.code === 'SCHEMA_TTL_INVALID'));

    assert.equal(fs.existsSync(allowlistPath), false);
  });

  test('TTL outside the allowed window is rejected', async () => {
    const { pipeline, allowlistPath } = pipelineFixture();
    const mutation = allowlistMutation({ ttlMs: DEFAULT_LIMITS.maxTtlMs + 1 });
    const intent = pipeline.submitIntent(mutation);

    const result = await pipeline.applyIntent(intent.id, mutation);

    assert.equal(result.applied, false);
    assert.ok(result.violations.some((v) => v.code === 'TTL_OUT_OF_BOUNDS'));
    assert.equal(fs.existsSync(allowlistPath), false);
  });

  test('oversized mutation is rejected', async () => {
    const { pipeline, allowlistPath } = pipelineFixture({
      limits: { maxSizeBytes: 256 },
    });
    const mutation = allowlistMutation({ payload: { note: 'x'.repeat(1024) } });
    const intent = pipeline.submitIntent(mutation);

    const result = await pipeline.applyIntent(intent.id, mutation);

    assert.equal(result.applied, false);
    assert.ok(result.violations.some((v) => v.code === 'SIZE_EXCEEDED'));
    assert.equal(fs.existsSync(allowlistPath), false);
  });
});

describe('two-phase pipeline: advisory hook (interface only)', () => {
  test('a rejecting hook vetoes an otherwise valid mutation', async () => {
    const { pipeline, allowlistPath } = pipelineFixture({
      advisory: { check: () => ({ verdict: 'reject', reason: 'looks wrong' }) },
    });
    const mutation = allowlistMutation();
    const intent = pipeline.submitIntent(mutation);

    const result = await pipeline.applyIntent(intent.id, mutation);

    assert.equal(result.applied, false);
    assert.equal(result.stage, 'advisory');
    assert.equal(result.code, 'ADVISORY_REJECT');
    assert.equal(fs.existsSync(allowlistPath), false);
  });

  test('the advisory layer is never the sole gate: its allow cannot rescue a failed check', async () => {
    const calls = [];
    const { pipeline, allowlistPath } = pipelineFixture({
      advisory: {
        check: (context) => {
          calls.push(context);
          return { verdict: 'allow' };
        },
      },
    });
    const mutation = allowlistMutation({ origin: 'https://not-intended.example' });
    const intent = pipeline.submitIntent(mutation);

    const result = await pipeline.applyIntent(intent.id, mutation);

    assert.equal(result.applied, false);
    assert.equal(result.stage, 'checks');
    assert.equal(calls.length, 0, 'deterministic failure must short-circuit the hook');
    assert.equal(fs.existsSync(allowlistPath), false);
  });

  test('a throwing hook fails closed', async () => {
    const { pipeline, allowlistPath } = pipelineFixture({
      advisory: {
        check: () => {
          throw new Error('model unavailable');
        },
      },
    });
    const mutation = allowlistMutation();
    const intent = pipeline.submitIntent(mutation);

    const result = await pipeline.applyIntent(intent.id, mutation);

    assert.equal(result.applied, false);
    assert.equal(result.code, 'ADVISORY_REJECT');
    assert.match(result.reason, /model unavailable/);
    assert.equal(fs.existsSync(allowlistPath), false);
  });

  test('with no hook configured the deterministic checks decide alone', async () => {
    const { pipeline } = pipelineFixture();
    const mutation = allowlistMutation();
    const intent = pipeline.submitIntent(mutation);

    const result = await pipeline.applyIntent(intent.id, mutation);
    assert.equal(result.applied, true);
    assert.equal(result.advisoryVerdict, 'abstain');
  });
});

describe('two-phase pipeline: apply + hash-chained log', () => {
  test('a verified mutation lands on disk and in the chain', async () => {
    const { pipeline, allowlistPath } = pipelineFixture();
    const mutation = allowlistMutation();
    const intent = pipeline.submitIntent(mutation);

    const result = await pipeline.applyIntent(intent.id, mutation);

    assert.equal(result.applied, true);
    assert.equal(result.seq, 1);
    const doc = JSON.parse(fs.readFileSync(allowlistPath, 'utf8'));
    assert.equal(doc.entries.length, 1);
    assert.equal(doc.entries[0].origin, 'https://example.com');
    assert.equal(doc.entries[0].intentId, intent.id);

    const chain = pipeline.verifyChain();
    assert.equal(chain.ok, true);
    assert.equal(chain.count, 1);
  });

  test('re-applying for the same origin upserts instead of duplicating', async () => {
    const { pipeline, allowlistPath } = pipelineFixture();
    for (let i = 0; i < 2; i += 1) {
      const mutation = allowlistMutation({ label: `run-${i}` });
      const intent = pipeline.submitIntent(mutation);
      await pipeline.applyIntent(intent.id, mutation);
    }
    const doc = JSON.parse(fs.readFileSync(allowlistPath, 'utf8'));
    assert.equal(doc.entries.length, 1);
    assert.equal(doc.entries[0].label, 'run-1');
    assert.equal(pipeline.verifyChain().count, 2);
  });

  test('a corrupt state file fails closed instead of being overwritten', async () => {
    const { pipeline, allowlistPath } = pipelineFixture();
    fs.writeFileSync(allowlistPath, 'not json at all');

    const mutation = allowlistMutation();
    const intent = pipeline.submitIntent(mutation);
    const result = await pipeline.applyIntent(intent.id, mutation);

    assert.equal(result.applied, false);
    assert.equal(result.stage, 'apply');
    assert.equal(result.code, 'APPLY_FAILED');
    assert.equal(fs.readFileSync(allowlistPath, 'utf8'), 'not json at all');
  });

  test('config.put merges payload under the same two-phase rules', async () => {
    const { pipeline } = pipelineFixture();
    const mutation = {
      kind: 'config.put',
      ttlMs: 5_000,
      payload: { fillTimeoutMs: 30_000 },
    };
    const intent = pipeline.submitIntent(mutation);
    const result = await pipeline.applyIntent(intent.id, mutation);

    assert.equal(result.applied, true);
    const doc = JSON.parse(fs.readFileSync(path.join(path.dirname(result.path), 'config.json'), 'utf8'));
    assert.equal(doc.data.fillTimeoutMs, 30_000);
  });
});

describe('pipeline wiring', () => {
  test('onApplied hands the written path back to the attestation observer', async () => {
    const seen = [];
    const pipeline = new StatePipeline({
      storeDir: tempDir(),
      intendedOrigins: ['https://example.com'],
      onApplied: (target, entry) => seen.push({ target, entry }),
    });
    const mutation = allowlistMutation();
    const intent = pipeline.submitIntent(mutation);
    const result = await pipeline.applyIntent(intent.id, mutation);

    assert.equal(seen.length, 1);
    assert.equal(seen[0].target, result.path);
    assert.equal(seen[0].entry.seq, result.seq);
  });
});
