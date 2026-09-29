'use strict';

const { test, describe, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { cleanupTempDirs, tempDir, allowlistMutation } = require('./helpers');
const { StatePipeline } = require('../src/state/pipeline');
const {
  HashChain,
  entryHash,
  readChainFile,
} = require('../src/state/chain');

after(cleanupTempDirs);

async function chainFixture(entryCount = 3) {
  const storeDir = tempDir();
  const chainPath = path.join(storeDir, 'state-chain.jsonl');
  const pipeline = new StatePipeline({
    storeDir,
    chainPath,
    intendedOrigins: ['https://example.com'],
  });
  for (let i = 0; i < entryCount; i += 1) {
    const mutation = allowlistMutation({ label: `n${i}` });
    const intent = pipeline.submitIntent(mutation);
    const result = await pipeline.applyIntent(intent.id, mutation);
    assert.equal(result.applied, true);
  }
  return { storeDir, chainPath, pipeline };
}

function rewriteChain(chainPath, mutate) {
  const entries = readChainFile(chainPath);
  mutate(entries);
  fs.writeFileSync(chainPath, entries.map((entry) => JSON.stringify(entry)).join('\n') + '\n');
}

describe('hash-chained state log', () => {
  test('a fresh chain verifies', async () => {
    const { pipeline } = await chainFixture(3);
    const result = pipeline.verifyChain();
    assert.equal(result.ok, true);
    assert.equal(result.count, 3);
  });

  test('an edited log entry is detected (issue #3 AC5)', async () => {
    const { pipeline, chainPath } = await chainFixture(3);

    rewriteChain(chainPath, (entries) => {
      entries[1].payload.origin = 'https://attacker.example';
    });

    const result = pipeline.verifyChain();
    assert.equal(result.ok, false);
    assert.equal(result.brokenAt, 2);
    assert.equal(result.reason, 'content-hash');
  });

  test('an edited entry with a recomputed hash is caught by the next link', async () => {
    const { pipeline, chainPath } = await chainFixture(3);

    rewriteChain(chainPath, (entries) => {
      entries[0].payload.origin = 'https://attacker.example';
      entries[0].hash = entryHash(entries[0]);
    });

    const result = pipeline.verifyChain();
    assert.equal(result.ok, false);
    assert.equal(result.brokenAt, 2);
    assert.equal(result.reason, 'prev-hash');
  });

  test('a deleted middle entry is detected as a sequence break', async () => {
    const { pipeline, chainPath } = await chainFixture(3);

    rewriteChain(chainPath, (entries) => {
      entries.splice(1, 1);
    });

    const result = pipeline.verifyChain();
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'sequence');
  });

  test('a tampered timestamp is detected even if the payload is untouched', async () => {
    const { pipeline, chainPath } = await chainFixture(2);

    rewriteChain(chainPath, (entries) => {
      entries[0].ts = '1970-01-01T00:00:00.000Z';
    });

    const result = pipeline.verifyChain();
    assert.equal(result.ok, false);
    assert.equal(result.brokenAt, 1);
    assert.equal(result.reason, 'content-hash');
  });

  test('HashChain.verify also works on an in-memory array', () => {
    const chain = new HashChain();
    chain.append({ kind: 'config.put' });
    chain.append({ kind: 'allowlist.add' });
    assert.equal(chain.verify().ok, true);

    chain.entries[0].payload.kind = 'allowlist.nuke';
    assert.equal(HashChain.verify(chain.entries).ok, false);
  });
});
