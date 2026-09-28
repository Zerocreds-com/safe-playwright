'use strict';

/**
 * External verifier process — deliberately separate from the daemon.
 *
 * Usage:
 *   node src/cli/verifier.js \
 *     --root <repo-root> \
 *     --manifest manifest.signed.json \
 *     --pubkey manifest.pub.pem \
 *     --store <state-dir> \
 *     [--chain <chain-file>] \
 *     [--origin https://example.com]... \
 *     [--alerts <alerts.jsonl>] \
 *     [--port 8787] [--rehash-interval 30000] \
 *     [--daemon-heartbeat <file> --daemon-ttl 30000] \
 *     [--self-heartbeat <file>]
 *
 * Exit code 2 = spawn-time attestation failed (fail closed, do not start).
 */

const fs = require('node:fs');
const path = require('node:path');
const { AlertChannel } = require('../attestation/alert-channel');
const { Verifier } = require('../attestation/verifier');
const { DeadManWatch } = require('../attestation/deadman');
const { startVerifierServer } = require('../attestation/server');
const { StatePipeline } = require('../state/pipeline');
const { writeHeartbeat } = require('../util/heartbeat');

function parseArgs(argv) {
  const options = { origins: [], rehashInterval: 30_000, daemonTtl: 30_000, port: 8787 };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      const value = argv[i + 1];
      if (value === undefined) throw new Error(`missing value for ${arg}`);
      i += 1;
      return value;
    };
    switch (arg) {
      case '--root': options.root = next(); break;
      case '--manifest': options.manifest = next(); break;
      case '--pubkey': options.pubkey = next(); break;
      case '--store': options.store = next(); break;
      case '--chain': options.chain = next(); break;
      case '--origin': options.origins.push(next()); break;
      case '--alerts': options.alerts = next(); break;
      case '--port': options.port = Number(next()); break;
      case '--rehash-interval': options.rehashInterval = Number(next()); break;
      case '--daemon-heartbeat': options.daemonHeartbeat = next(); break;
      case '--daemon-ttl': options.daemonTtl = Number(next()); break;
      case '--self-heartbeat': options.selfHeartbeat = next(); break;
      default: throw new Error(`unknown argument: ${arg}`);
    }
  }
  for (const key of ['root', 'manifest', 'pubkey', 'store']) {
    if (!options[key]) throw new Error(`missing required argument --${key}`);
  }
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));

  const alertChannel = new AlertChannel({
    filePath: options.alerts || path.join(options.store, 'alerts.jsonl'),
    emitter: 'verifier',
  });
  alertChannel.onAlert((alert) => {
    process.stdout.write(`ALERT ${alert.kind} ${JSON.stringify(alert.detail)}\n`);
  });

  const signedManifest = JSON.parse(fs.readFileSync(options.manifest, 'utf8'));
  const publicKeyPem = fs.readFileSync(options.pubkey, 'utf8');
  const verifier = new Verifier({
    rootDir: options.root,
    signedManifest,
    publicKeyPem,
    alertChannel,
  });

  const spawn = verifier.spawnCheck();
  if (!spawn.ok) {
    process.stderr.write(`spawn-time attestation FAILED: ${JSON.stringify(spawn)}\n`);
    process.exit(2);
  }
  process.stdout.write(`spawn-time attestation OK (${signedManifest.manifest.files.length} files)\n`);

  const pipeline = new StatePipeline({
    storeDir: options.store,
    chainPath: options.chain,
    intendedOrigins: options.origins,
    onApplied: (target) => verifier.recordState(target),
  });

  // State files written by earlier runs must be covered from the start.
  for (const name of fs.readdirSync(options.store)) {
    if (name.endsWith('.json')) verifier.recordState(path.join(options.store, name));
  }

  verifier.startRehash(options.rehashInterval);

  const handle = await startVerifierServer({ pipeline, port: options.port });
  process.stdout.write(`verifier listening on ${handle.url}\n`);

  const watches = [];
  if (options.daemonHeartbeat) {
    const watch = new DeadManWatch({
      heartbeatPath: options.daemonHeartbeat,
      ttlMs: options.daemonTtl,
      alertChannel,
      subject: 'daemon',
    });
    watch.start();
    watches.push(watch);
  }

  let selfBeat = null;
  if (options.selfHeartbeat) {
    selfBeat = setInterval(
      () => writeHeartbeat(options.selfHeartbeat),
      Math.max(1000, Math.floor(options.daemonTtl / 2))
    );
    if (typeof selfBeat.unref === 'function') selfBeat.unref();
    writeHeartbeat(options.selfHeartbeat);
  }

  const shutdown = async () => {
    verifier.stopRehash();
    watches.forEach((watch) => watch.stop());
    if (selfBeat) clearInterval(selfBeat);
    await handle.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((err) => {
  process.stderr.write(`${err.message}\n`);
  process.exit(1);
});
