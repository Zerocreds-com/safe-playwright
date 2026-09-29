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
  {
    id: 'no-remote-debugging-address-in-launch-path',
    files: LAUNCH_PATH,
    pattern: /--remote-debugging-address/,
    why:
      'binding CDP to a non-loopback address exposes the debugging endpoint ' +
      'to the network; the flag behaves differently per Chromium binary ' +
      '(playwright#39802) — pipe transport only',
  },
  {
    id: 'no-code-exec-sinks-in-src',
    files: 'src/**',
    // The lookbehind allows Playwright's page.$eval / page.evaluate while
    // banning a real eval( call.
    pattern: /(?<![.$\w])eval\s*\(|new\s+Function\s*\(|node:vm|require\(\s*['"]vm['"]|runInContext/,
    why:
      'driver-side code-exec sinks are how browser_run_code-style RCE happens ' +
      '(playwright-mcp#1495: vm sandbox escape via the prototype chain)',
  },
  {
    id: 'no-file-urls',
    files: '**',
    pattern: /file:\/\//,
    why:
      'file:// navigation is the local-file-read half of the agent SSRF class ' +
      '(mcp-playwright#209, playwright-mcp#1626) — no code path may use it',
  },
  {
    id: 'no-bind-all',
    files: 'src/**',
    pattern: /0\.0\.0\.0/,
    why:
      'host code binds loopback only (127.0.0.1) — binding all interfaces ' +
      'makes internal services reachable (SSRF class, attack-cases doc §1.5)',
  },
  {
    id: 'no-tls-blindfold',
    files: '**',
    pattern: /ignoreHTTPSErrors/,
    why:
      'disabling TLS verification removes the only signal against MITM on the ' +
      'navigation/download path (CVE-2025-59288 class)',
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
  if (typeof rule.files === 'string') {
    if (rule.files.endsWith('/**')) return relPath.startsWith(rule.files.slice(0, -2));
    return relPath === rule.files;
  }
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
