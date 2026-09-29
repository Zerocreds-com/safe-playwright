Goal: Bootstrap safe-playwright repo and land the sensitive-data proxy feasibility research (PR #1, tracking issue #2)

- [x] CI green on https://github.com/Zerocreds-com/safe-playwright/pull/1
- [x] Merged to main
- [x] Research doc verified live — matrix has sources, PR + tracking issue linked (https://github.com/Zerocreds-com/safe-playwright/issues/2)

Goal: P2 external attestation + two-phase state verification (issue #3)

- [x] CI green on https://github.com/Zerocreds-com/safe-playwright/pull/10 (6/6: policy-lint, 4× test matrix, aggregate `ci`)
- [x] Tests green — `npm test` (51 after merge with P4: attestation, pipeline, chain, dead-man, HTTP integration + fill-handoff)
- [x] Issue #3 acceptance criteria covered (test table in PR #10)
- [x] Merged to main

Goal: P4 fill browser + storage-state handoff PoC (issue #5, epic #2)

- [x] PR: https://github.com/Zerocreds-com/safe-playwright/pull/11 — tests 8/8, demo 13/13
- [x] Merged to main; CI green on main (workflow landed later in PR #12)
- [x] Issue #5 acceptance boxes checked off in the issue (separate-OS-user blocker documented in docs/p4-fill-browser-storage-state-handoff-poc.md)

Goal: CI baseline (test matrix + policy ratchet, epic #2 C9)

- [x] PR: https://github.com/Zerocreds-com/safe-playwright/pull/12 — all jobs green
- [x] Branch protection on main: ruleset requires the `ci` check
- [ ] npm audit + Dependabot + signed-manifest release jobs (next step)
- [ ] Differential canary runs in CI — belongs to P3 (#4)

Goal: Common Playwright attack-cases survey + supply-chain hardening

- [x] Survey doc + coverage matrix: docs/common-playwright-attack-cases-and-defenses.md (12 cases)
- [x] policy-lint extended to 10 rules (debugging-address, code-exec sinks, file://, bind-all, TLS blindfold) — mutation-tested
- [x] CI: supply-chain job (npm ci --ignore-scripts + npm audit --audit-level=high) + Dependabot (npm, github-actions)
- [x] P4 test asserts the login server binds loopback only
- [x] Open items filed: issue #14 (browser-install integrity CVE-2025-59288, @playwright/mcp pin CVE-2025-9611)
- [ ] PR CI green and merged
