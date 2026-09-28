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

Research complete (PR #1). Implementation started with P2 — external
attestation and two-phase state verification (issue #3): run `npm test`
(Node ≥ 20, no dependencies). Later phases (P3–P7) follow the verdicts in
the checklist.

## Language

Everything in this repo — documentation, code, comments, commit and PR messages —
is written in English.

## License

MIT
