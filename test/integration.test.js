'use strict';

const { test, describe, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { cleanupTempDirs, tempDir, allowlistMutation } = require('./helpers');
const { startVerifierServer } = require('../src/attestation/server');
const { StatePipeline } = require('../src/state/pipeline');
const { IntentClient } = require('../src/daemon/intent-client');

after(cleanupTempDirs);

async function withVerifier(options, fn) {
  const storeDir = tempDir();
  const pipeline = new StatePipeline({
    storeDir,
    intendedOrigins: ['https://example.com'],
    ...options,
  });
  const handle = await startVerifierServer({ pipeline });
  try {
    await fn({ handle, pipeline, storeDir, client: new IntentClient({ baseUrl: handle.url }) });
  } finally {
    await handle.close();
  }
}

describe('verifier exposed over the process boundary', () => {
  test('the daemon client applies a mutation through the two phases', async () => {
    await withVerifier({}, async ({ client, storeDir }) => {
      const mutation = allowlistMutation();
      const result = await client.mutate(mutation);

      assert.equal(result.applied, true);
      assert.equal(result.stage, 'applied');
      const doc = JSON.parse(fs.readFileSync(path.join(storeDir, 'allowlist.json'), 'utf8'));
      assert.equal(doc.entries[0].origin, 'https://example.com');
      const chainLines = fs
        .readFileSync(path.join(storeDir, 'state-chain.jsonl'), 'utf8')
        .split('\n')
        .filter(Boolean);
      assert.equal(chainLines.length, 1);
      assert.equal(JSON.parse(chainLines[0]).seq, 1);
    });
  });

  test('an apply request with no intent is refused and touches no file (AC4)', async () => {
    await withVerifier({}, async ({ handle, storeDir }) => {
      const response = await fetch(`${handle.url}/apply`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ intentId: 'not-a-real-intent', mutation: allowlistMutation() }),
      });
      const payload = await response.json();

      assert.equal(response.status, 409);
      assert.equal(payload.applied, false);
      assert.equal(payload.code, 'INTENT_NOT_FOUND');
      assert.equal(fs.existsSync(path.join(storeDir, 'allowlist.json')), false);
      assert.deepEqual(fs.readdirSync(storeDir), []);
    });
  });

  test('an intent does not travel: swapping the mutation on apply is refused', async () => {
    await withVerifier({}, async ({ client, storeDir }) => {
      const intent = await client.submitIntent(allowlistMutation());
      const result = await client.applyIntent(
        intent.id,
        allowlistMutation({ origin: 'https://evil.example' })
      );

      assert.equal(result.applied, false);
      assert.equal(result.code, 'INTENT_MUTATION_MISMATCH');
      assert.equal(fs.existsSync(path.join(storeDir, 'allowlist.json')), false);
    });
  });

  test('policy rejections survive the transport intact', async () => {
    await withVerifier({}, async ({ client, storeDir }) => {
      const mutation = allowlistMutation({ origin: 'https://not-intended.example' });
      const result = await client.mutate(mutation);

      assert.equal(result.applied, false);
      assert.equal(result.stage, 'checks');
      assert.ok(result.violations.some((v) => v.code === 'ORIGIN_NOT_INTENDED'));
      assert.equal(fs.existsSync(path.join(storeDir, 'allowlist.json')), false);
    });
  });

  test('health endpoint reports the verifier component', async () => {
    await withVerifier({}, async ({ handle }) => {
      const response = await fetch(`${handle.url}/health`);
      const payload = await response.json();
      assert.equal(response.status, 200);
      assert.equal(payload.component, 'verifier');
    });
  });
});
