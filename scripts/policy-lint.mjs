#!/usr/bin/env node
// policy-lint — static security ratchet for safe-playwright (epic #2 C9,
// checklist §6.2 "forbid outright", §6 option 5).
//
// Zero dependencies; run as `npm run policy:lint` or in CI. It scans
// code files only (src/, test/, scripts/) — documentation may *mention*
// any of these tokens freely. Optional first argument: another repository
// root to scan (used locally to check a different worktree/branch).
//
// Scope rules, stated honestly:
//   * Launch-path files must not *request* a debugging port or attach to
//     one — the auditor (src/port-audit.mjs) is allowed to *detect* the
//     flag, so it is excluded from that rule.
//   * The fill worker additionally must not use pixel-export APIs or
//     connectOverCDP (it launches its own sealed browser over the
//     Playwright pipe and nothing else).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(process.argv[2] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), '..'));
const SELF = fileURLToPath(import.meta.url);

const CODE_DIRS = ['src', 'test', 'scripts'];

// Files that launch or configure the fill browser.
const LAUNCH_PATH = ['src/audited-filler.mjs', 'src/handoff-runner.mjs'];
// The sealed fill worker — strictest surface.
const FILL_WORKER = 'src/audited-filler.mjs';

const RULES = [
  {
    id: 'no-remote-debugging-port-in-launch-path',
    files: LAUNCH_PATH,
    pattern: /--remote-debugging-port/,
    why:
      'launch-path code must never request a TCP debugging port — the fill ' +
      'browser runs over the Playwright pipe only (checklist §6 option 5)',
  },
  {
    id: 'no-exposed-devtools-protocol',
    files: '**',
    pattern: /exposeDevToolsProtocol/,
    why: 'Target.exposeDevToolsProtocol is forbidden outright (checklist §6.2)',
  },
  {
    id: 'no-pixel-export-in-fill-worker',
    files: [FILL_WORKER],
    pattern: /\.screenshot\(|recordVideo|tracing\.start/,
    why: 'no pixel export from the fill browser — OTP/PII are legible (U7)',
  },
  {
    id: 'no-cdp-attach-in-fill-worker',
    files: [FILL_WORKER],
    pattern: /connectOverCDP/,
    why:
      'the fill worker launches its own sealed browser; attaching over CDP ' +
      'would make it a client of a (possibly port-exposed) browser',
  },
  {
    id: 'no-focused-tests',
    files: 'test/**',
    pattern: /\.only\(/,
    why: 'focused tests (.only) silently skip the rest of the suite in CI',
  },
];

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
      out.push(...walk(full));
    } else if (/\.(js|mjs|cjs)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

function matches(relPath, rule) {
  if (rule.files === '**') return true;
  if (rule.files === 'test/**') return relPath.startsWith('test/');
  return rule.files.includes(relPath);
}

const violations = [];
let scannedFiles = 0;
let evaluatedRules = 0;

for (const dir of CODE_DIRS) {
  const abs = path.join(ROOT, dir);
  if (!fs.existsSync(abs)) continue;
  for (const file of walk(abs)) {
    if (file === SELF) continue;
    const relPath = path.relative(ROOT, file);
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    for (const rule of RULES) {
      if (!matches(relPath, rule)) continue;
      evaluatedRules += 1;
      lines.forEach((line, index) => {
        if (rule.pattern.test(line)) {
          violations.push({
            rule: rule.id,
            file: relPath,
            line: index + 1,
            why: rule.why,
            snippet: line.trim().slice(0, 160),
          });
        }
      });
    }
    scannedFiles += 1;
  }
}

if (violations.length > 0) {
  console.error(`policy-lint: ${violations.length} violation(s)\n`);
  for (const v of violations) {
    console.error(`  ${v.rule}`);
    console.error(`    ${v.file}:${v.line}`);
    console.error(`    ${v.snippet}`);
    console.error(`    why: ${v.why}\n`);
  }
  process.exit(1);
}

console.log(
  `policy-lint: OK — ${scannedFiles} code file(s), ${RULES.length} rule(s), ` +
    `${evaluatedRules} rule/file combination(s) checked`,
);
