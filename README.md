# safe-playwright

**Playwright proxy layer — the browser fills sensitive data while the agent, the driver and the LLM never see it.**

ZeroCreds' idea ("the bot uses a password without seeing it") applied to browser
automation: when a Playwright session needs to type a password, an OTP, a card
number or any other sensitive value into a page, the value comes from an
auditable credential store at the moment of filling — it never enters the LLM
context, never sits in the Playwright driver's memory, and (per threat tier) may
never even reach the page DOM.

## Why this exists

Every AI browser agent eventually hits the same wall: the model must log in
somewhere. The obvious implementations are all wrong in one of these ways:

| Approach | What's wrong |
|---|---|
| Password typed in chat | Secret is in the LLM prompt forever |
| Password passed as an MCP tool argument | Secret crosses the model context on every call |
| Password in driver env vars | Any `printenv`, core dump or log line leaks it |
| Password autofilled by the browser | `page.evaluate(() => input.value)` reads it back |

The guarantee this project researches and builds toward:

> **Only audited code can touch a credential, and its access is reliably
> controlled** — not just by a protected build, but by canary credentials with
> access alerts, append-only audit logs, and open-source implementations that
> anyone can verify.

## What will live here

- `docs/sensitive-data-proxy-feasibility-checklist.md` — the research:
  a census of every Playwright / `@playwright/mcp` / CDP data-entry method,
  crossed with every possible interposition point, graded ✅ / ⚠️ / ❌ against
  a 4-tier threat model (LLM context → driver process → page DOM/CDP → network).
- `src/` — the proxy layer implementation (design follows from the research).
  P2 first: an **external verifier** process separate from the daemon
  (`src/attestation/` — signed-manifest spawn check, periodic re-hash,
  verifier-owned alerts, dead-man heartbeat; `src/cli/verifier.js` to run it)
  and a **two-phase state mutation pipeline** (`src/state/` — intent →
  deterministic checks → advisory hook → apply → hash-chained log) with the
  daemon talking to it only over `src/daemon/intent-client.js`.

## Status

Research landed (PR #1). First implementation phase is in progress:
P2 external attestation (#3) and **P4 fill browser + storage-state
handoff (#5)** — see the PoC below.

## P4 PoC: fill browser + storage-state handoff (issue #5)

The universal default from the checklist verdict (§6.1): **the credential
never exists in the agent's browser.** A dedicated fill worker performs the
whole login in its own process; the agent's browser is born with
`storage-state`.

### Flow

```
 cred file (0600)          local test login server
        │                          ▲
        ▼                          │ login flow (password, OTP, CAPTCHA)
 ┌──────────────────────────┐      │
 │ audited fill worker      │──────┘
 │ src/audited-filler.mjs   │  separate process (optionally slot OS user)
 │ Playwright default pipe  │  --remote-debugging-pipe, ZERO TCP ports
 │ no pixel export          │  screenshots/video/tracing policy-blocked
 └────────────┬─────────────┘
              │ storage-state (0600, cookies only — never the password)
              ▼
 ┌──────────────────────────┐
 │ agent browser            │  born with storageState: authenticated,
 │ page.evaluate(...)       │  password absent from DOM/storage/cookies
 └──────────────────────────┘
```

### Run it

```bash
npm install
npx playwright install chromium
npm test    # full acceptance test (test/p4-fill-browser-handoff.test.mjs)
npm run demo  # narrative walkthrough of the same flow
```

The PoC only ever talks to a loopback test server
(`src/local-login-server.mjs`) — it never hits a real site.

### What the test asserts (issue #5 acceptance criteria)

| Criterion | Where |
|---|---|
| Login through the fill browser; agent-side evaluate finds no password in the DOM | `test/p4-fill-browser-handoff.test.mjs` — `agent browser is authenticated…` |
| Fill browser has no listening TCP port (audited twice: worker-side and independent, while the browser is alive) | `fill worker performs the login…` |
| Separate OS user, or a documented blocker | `fill browser runs as a different OS user…` + docs |
| `storage-state` handoff authenticates the agent without the credential | `storage-state handoff artifact…` |
| Post-fill hygiene (L5): navigation happened, field empty on return | `report: post-fill hygiene (L5)…` |
| Demo script + this README section | `scripts/p4-fill-handoff-demo.mjs`, this section |

### Separate OS user — current blocker

The PoC *attempts* the slot-user switch (`SAFE_PLAYWRIGHT_SLOT_USER`,
`src/slot-user.mjs`); in this environment it is **blocked**: creating an OS
user or switching uid needs root, and non-interactive `sudo -n` is not
available (a password would be required). The test accepts either outcome
— a real uid split, or this blocker — and the blocker is documented in
`docs/p4-fill-browser-storage-state-handoff-poc.md` with the production
remediation. Until then the filler runs as the same uid as the agent.

### Residual risks (by design)

- The fill browser's page sees the password during fill (L1, domain
  trust) — accepted in the checklist.
- The session cookie *is* handed to the agent browser (U5): cookies are
  bearer secrets; P3 return-path controls stay active after handoff.
- Second-CDP-attach enforcement on persistent port-exposed Chrome remains
  out of scope here → epic #2 brainstorm.

## Language

Everything in this repo — documentation, code, comments, commit and PR messages —
is written in English.

## License

MIT
