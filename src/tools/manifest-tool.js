'use strict';

/**
 * Manifest tooling — generate signing keys, build + sign a manifest, verify
 * one against a root directory.
 *
 *   node src/tools/manifest-tool.js keygen --out <dir>
 *   node src/tools/manifest-tool.js sign --root <dir> --key <pem> \
 *       --out manifest.signed.json <rel-path>...
 *   node src/tools/manifest-tool.js verify --root <dir> \
 *       --manifest manifest.signed.json --pubkey <pem>
 */

const fs = require('node:fs');
const path = require('node:path');
const {
  generateKeyPair,
  buildManifest,
  signManifest,
  verifyManifestSignature,
  checkManifestFiles,
} = require('../attestation/manifest');

function parseArgs(argv) {
  const options = { files: [] };
  options.command = argv[0];
  for (let i = 1; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      const value = argv[i + 1];
      if (value === undefined) throw new Error(`missing value for ${arg}`);
      i += 1;
      return value;
    };
    switch (arg) {
      case '--out': options.out = next(); break;
      case '--root': options.root = next(); break;
      case '--key': options.key = next(); break;
      case '--manifest': options.manifestPath = next(); break;
      case '--pubkey': options.pubkey = next(); break;
      default: options.files.push(arg);
    }
  }
  return options;
}

function main() {
  const options = parseArgs(process.argv.slice(2));

  if (options.command === 'keygen') {
    const dir = options.out || '.';
    fs.mkdirSync(dir, { recursive: true });
    const { publicKeyPem, privateKeyPem } = generateKeyPair();
    const privPath = path.join(dir, 'manifest.key.pem');
    const pubPath = path.join(dir, 'manifest.pub.pem');
    fs.writeFileSync(privPath, privateKeyPem, { mode: 0o600 });
    fs.writeFileSync(pubPath, publicKeyPem);
    process.stdout.write(`wrote ${privPath}\nwrote ${pubPath}\n`);
    return;
  }

  if (options.command === 'sign') {
    if (!options.root || !options.key || !options.out || options.files.length === 0) {
      throw new Error('sign requires --root, --key, --out and at least one file path');
    }
    const manifest = buildManifest({ rootDir: options.root, files: options.files });
    const signed = signManifest(manifest, fs.readFileSync(options.key, 'utf8'));
    fs.writeFileSync(options.out, JSON.stringify(signed, null, 2) + '\n');
    process.stdout.write(`signed ${manifest.files.length} files -> ${options.out}\n`);
    return;
  }

  if (options.command === 'verify') {
    if (!options.root || !options.manifestPath || !options.pubkey) {
      throw new Error('verify requires --root, --manifest and --pubkey');
    }
    const signed = JSON.parse(fs.readFileSync(options.manifestPath, 'utf8'));
    const publicKeyPem = fs.readFileSync(options.pubkey, 'utf8');
    const signature = verifyManifestSignature(signed, publicKeyPem);
    if (!signature.ok) {
      process.stderr.write(`signature INVALID (${signature.reason})\n`);
      process.exit(2);
    }
    const report = checkManifestFiles(signed.manifest, options.root);
    if (!report.ok) {
      process.stderr.write(`file check FAILED: ${JSON.stringify(report.mismatches, null, 2)}\n`);
      process.exit(2);
    }
    process.stdout.write(`OK — signature valid, ${signed.manifest.files.length} files match\n`);
    return;
  }

  throw new Error(`unknown command: ${options.command}`);
}

try {
  main();
} catch (err) {
  process.stderr.write(`${err.message}\n`);
  process.exit(1);
}
