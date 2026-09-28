# P4 PoC — fill browser + storage-state handoff (issue #5)

Implementation note for the PoC built per
[issue #5](https://github.com/Zerocreds-com/safe-playwright/issues/5)
(epic [#2](https://github.com/Zerocreds-com/safe-playwright/issues/2),
checklist §2 P5+P2 and §6.1). This document covers what was built, what the
test proves, the separate-OS-user blocker, and what is deliberately out of
scope.

## 1. Design: two browsers, one handoff

| | Fill browser | Agent browser |
|---|---|---|
| Process | `src/audited-filler.mjs` (own Node process, spawn) | test/demo process (`chromium.launch` + `storageState`) |
| Transport | Playwright default `--remote-debugging-pipe` (fds), **zero TCP ports** | Playwright default pipe as well |
| OS user | dedicated slot user when feasible (§4), else same uid (documented blocker) | agent uid |
| Sees the password | yes — it fills it (L1, domain trust) | **never** |
| Pixels | forbidden (policy + runtime tripwire) | allowed (agent side, no credential pages) |
| Content after login | session cookie only (browser destroyed after handoff) | `storage-state`: cookies + localStorage, **no credential** |

The whole auth flow (password fill, OTP via a human channel, CAPTCHA)
happens inside the fill worker. On success it exports
`browserContext.storageState()` to a `0600` file and exits; the agent's
browser is launched *with* that state (`newContext({ storageState })`), so
it is born authenticated and has no login flow of its own.

### Components

- `src/audited-filler.mjs` — the audited filler: reads the credential from
  a `0600` file (never argv/env/stdout), performs the login, asserts L5
  hygiene, exports storage-state, runs a transport audit while the browser
  is still open, writes `fill-report.json`, then holds the browser open
  until the parent closes stdin (so the parent can audit independently).
- `src/local-login-server.mjs` — loopback-only test login server (form,
  session cookie, `/dashboard`, `/whoami`, `/stats`). The PoC never
  contacts a real site.
- `src/port-audit.mjs` — walks a process tree (`ps`) and collects
  listening TCP ports (`lsof` on macOS, `/proc` on Linux) plus the browser
  command lines (`--remote-debugging-pipe` / `--remote-debugging-port`).
- `src/slot-user.mjs` — separate-OS-user detection and spawn construction.
- `src/handoff-runner.mjs` — orchestration shared by test and demo:
  spawn filler → audit live → release → agent-side verification.
- `test/p4-fill-browser-handoff.test.mjs` — the acceptance test.
- `scripts/p4-fill-handoff-demo.mjs` — narrative demo (`npm run demo`).

## 2. Invariants enforced (checklist §5, epic C10/C11)

1. **Secret browser = pipe, no TCP ports.** The fill browser is asserted
   *twice*: by the worker itself (report) and independently by the parent
   test while the worker's browser is still alive — both must find
   `--remote-debugging-pipe`, no `--remote-debugging-port` flag, and zero
   listening TCP sockets in the whole process tree.
2. **Port-exposed browsers carry no secrets.** Not exercised as an attack
   surface here because the PoC has no port-exposed browser at all — the
   persistent noVNC Chrome is explicitly never a fill target (issue notes).
   The agent browser (pipe, cookie-only) is asserted to have no credential
   in DOM/storage/cookies after handoff.
3. **No pixel export from the fill browser**: static token scan over the
   worker source + runtime tripwire (screenshot / video / tracing patched
   to throw) + `forbiddenApisCalled` asserted empty.
4. **Credential plumbing**: password travels only as a file path; asserted
   absent from the worker argv and from the storage-state/report JSON.

### Connection accounting (issue scope item 4)

Not implemented in this PoC — deliberately. Rationale: with pipe transport
the CDP endpoint is two file descriptors inherited by exactly one process;
there is no listening socket to attach to, so the "second client" problem
at the TCP level does not exist for the fill browser. Counting clients
only becomes meaningful for the persistent port-exposed Chrome, whose
enforcement mechanism is explicitly deferred to the epic #2 brainstorm
(issue notes: "Second-CDP-attach enforcement details are intentionally out
of scope here"). This document records that decision rather than silently
dropping it.

## 3. Threat-tier mapping (checklist §1.1, §2 P5)

| Tier | Fill browser PoC |
|---|---|
| T0 LLM context | ✅ the demo/test prints no credential; the model would only ever see `cred://`-style references and the report |
| T1 driver process | ✅ for the *agent* driver — the filler is a separate minimal audited process holding the value instead |
| T2 page/CDP/pixels vs agent | ✅ agent-side `page.evaluate` proves the password is absent from DOM, storage and cookies after handoff |
| T2 during fill in the fill browser | ❌ accepted (L1, domain trust — the site must receive the password) |
| T3 network | normal TLS/HTTP to the target; the `0600` storage-state file is the disk residual |

## 4. Separate OS user — attempt and blocker

The PoC implements the switch (`SAFE_PLAYWRIGHT_SLOT_USER` +
`src/slot-user.mjs`): when the slot user exists *and* passwordless sudo is
available, the filler is spawned as
`sudo -n -u <slot-user> -- node src/audited-filler.mjs …`.

**Current blocker (this environment):** neither precondition holds —
`sudo -n true` fails ("a password is required"), and creating a dedicated
OS user needs root. Non-interactive uid switching is therefore impossible
here, so the filler runs under the same uid as the agent, and the test
asserts the alternative acceptance branch: a specific, documented blocker.

**Production remediation (pick one):**

- run the session's filler service *as* the slot user (no switch at run
  time), or
- grant the launcher passwordless `sudo -u <slot-user>` for exactly one
  command, or
- launch the whole session inside a container/namespace whose uid is the
  slot user.

Either removes the same-uid exposure of filler env/memory/core dumps
(epic C15 / threat U6).

## 5. Acceptance criteria results (issue #5)

Filled in by the test run — see `npm test` output and the PR.

| Criterion | Result |
|---|---|
| PoC demo: login via fill browser; agent-side session reads the page; password absent (evaluate finds empty field / no credential in DOM) | see PR |
| Fill browser process has no listening TCP port (verified in test) | see PR |
| Fill browser runs as a different OS user than the agent (or documented blocker) | see PR (§4) |
| `storage-state` handoff works: agent authenticated without ever seeing the credential | see PR |
| Post-fill hygiene: field cleared / navigation happened (L5) asserted | see PR |
| Demo script + README section | `scripts/p4-fill-handoff-demo.mjs`, README §P4 PoC |

## 6. Known limitations of the PoC

- The login flow models password-only auth; OTP/CAPTCHA channels are
  reserved for a human-in-the-loop extension (same fill browser, same
  handoff).
- The pixel-export tripwire is a tripwire, not a boundary — it stops our
  own code paths and fails loudly; a determined in-process caller could
  reach unpatched helpers. Enforcement hardening belongs with the CI
  ratchet (epic C9).
- URL-blocking the agent from re-opening login pages (checklist §2 P5
  failure mode) is not part of this issue.
