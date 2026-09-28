# Research task: sensitive-data proxy feasibility for Playwright (ZeroCreds-for-browser pattern)

You are doing a **research task** in the freshly bootstrapped repo `~/Code/safe-playwright`.
No implementation code. Deliverable = one thorough research document + a PR + a tracking issue.

## Context

ZeroCreds' core idea: "the bot uses a password without seeing it" — credentials go
browser → HTTP → server-side file (0600) → short-lived handler → Playwright child env,
and never enter the LLM prompt/tool-args/tool-results.

Now we want the same guarantee applied to **Playwright browser automation in general**:
when an agent-driven Playwright session must type sensitive data into a page (login
password, OTP code, PII, card number, passport data...), the value should be supplied
by an auditable proxy layer **at fill time**, so that:

- the LLM never sees it (ZeroCreds level — already achievable today),
- the Playwright **driver process** ideally never holds it,
- and the page/CDP/network adversary model is documented honestly.

**Real requirement (user's words):** in the ideal nobody sees it; and even open-sourcing
the repo + protecting the build is a form of guarantee. The operative requirement:
**only audited code may see a credential, and its access must be reliably controlled —
not only by build integrity, but e.g. by fake/canary credentials with availability
alerts and audit logs.**

## Inputs (read these first)

1. `/Users/vova/Downloads/playwright_история_безопасность_и_гранулярный_доступ.md` —
   prior research: Playwright/CDP history, prompt-injection vectors, capability
   levels 0–5, Playwright Proxy Layer architecture sketch, scoped tokens/macaroons.
   Build on it, don't duplicate it wholesale.
2. The trained-assist-agent codebase (ZeroCreds implementation + Playwright usage):
   `/Users/vova/Code/.worktrees/trained-assist-agent/session-interesuet-takoy-vopros-po-20260928-221738`
   Key facts already established (verify only if needed, spend the time on the census instead):
   - ZeroCreds flow: `src/user-tokens.js:287-330` (generateConnectLink → ZeroCreds SaaS or legacy `~/connect-pending/<32hex>.json`), POST `/tokens` writes `~/agent-tokens/<uid>/<svc>` 0600 (`src/server.js:1147-1197`).
   - `browser_session_autologin` reads the file inside the MCP handler and passes it to `infra/browser-session/login.js` via child env `LOGIN_EMAIL`/`LOGIN_PASSWORD` (`src/mcp-skills/tools/21-browser-session.js:248-299`) — password NOT in LLM context.
   - Leaks in the current design (document as baseline gaps): `browser_session_login` takes password as LLM tool args (`21-browser-session.js:303-338`); `website_credentials_save` same (`98-api-from-website.js:67-89`); `loadUserTokens` catch-all injects raw credential JSON into engine env (`src/user-tokens.js:225`); `browser_session_capture_cookies` returns raw cookies as tool result (`21-browser-session.js:170-222`); driver can always read DOM/network via its CDP connection.
   - Playwright input patterns in use: `locator.fill` (`src/site-connector.js:160,164`), `page.evaluate` + `nativeInputValueSetter` + dispatchEvent for Vue/React (`src/nalog-login.js:181-189`, `src/getcourse-login.js:68-76`, `src/tilda-login.js:80-86`), `connectOverCDP('http://127.0.0.1:9224')` persistent Chrome (`infra/browser-session/login.js:18`), LLM-generated JS via `page.evaluate` (`src/mcp-skills/tools/21-browser-session.js:127-168`, `src/ru-edge.js:389`), `@playwright/mcp` mounted in every engine session (`src/browser.js:127-132`).
3. Upstream docs for the census: https://playwright.dev/docs/api (page/locator/keyboard/mouse classes), https://github.com/microsoft/playwright-mcp (tool list — check the pinned version's actual tools, repo uses `@playwright/mcp ^0.0.29`), CDP domains https://chromedevtools.github.io/devtools-protocol/ (Input, Runtime, Autofill, Page domains).

## Deliverable: `docs/sensitive-data-proxy-feasibility-checklist.md`

Required structure:

1. **Threat model — 4 tiers.** Who must NOT see the value:
   - T0 LLM context (prompt / tool args / tool results / logs visible to model)
   - T1 Playwright driver process (Node process memory, env, core dumps, `page.on('request')` bodies)
   - T2 page adversary (DOM read via `page.evaluate`, CDP owner, page JS on hostile site, screenshots/vision)
   - T3 network (proxy, request bodies after leaving the browser)
   Plus the cross-cutting requirement: only audited code touches creds (open source,
   protected/reproducible build, **canary credentials + access alerts**, append-only
   audit log). State explicitly which tiers a given interposition point can guarantee.
2. **Interposition points** (where a proxy layer can be inserted) — analyze at least:
   MCP-tool layer (intercept tool call before it reaches Playwright) · separate fill
   process attached over CDP · in-page bridge (`exposeBinding` / `addInitScript`) ·
   network-layer proxy (mitmproxy-style, inject into request body) · separate login
   browser + cookie/storage-state handoff to the agent's browser · OS-level input
   (xdotool etc. on the persistent noVNC Chrome) · browser password-manager/autofill
   (Chrome `Autofill` CDP domain / profile-stored creds) · Playwright `page.route`
   request interception. For each: which tiers it guarantees, what it costs, failure modes.
3. **Census of data-entry methods** — enumerate ALL of them yourself (this is the core
   work — the "156 ways" the user mentions is rhetorical; be exhaustive, expect 30–60
   rows). Groups to cover: `page.fill`/`locator.fill`/`fillSequentially` ·
   `page.type`/`pressSequentially` · `keyboard.type`/`insertText`/`press` ·
   `page.evaluate` value-assignment (plain, nativeInputValueSetter, React/Vue setters,
   dispatchEvent) · clipboard write + simulated paste · `setInputFiles` (file uploads —
   relevant for certificates, key files) · `selectOption`/`check`/`click`/`tap`/`dragTo` ·
   `page.route`/`route.fulfill` request-body rewrite · `setExtraHTTPHeaders` (Basic/Bearer
   auth) · URL-embedded credentials (`https://user:pass@host`) · CDP `Input.insertText`,
   `Input.dispatchKeyEvent`, `Runtime.evaluate`, `Page.addScriptToEvaluateOnNewDocument` ·
   `@playwright/mcp` tool calls (`browser_type`, `browser_click`, `browser_file_upload`,
   `browser_navigate`, ... — note `browser_evaluate` absence in 0.0.29 and
   `browser_generate_playwright_test` presence) · LLM-generated script executed by the
   driver (`browser_session_evaluate`, `ru_browser_fetch`) · autofill/password-manager
   population · form autofill heuristics · shadow-DOM/frame piercing variants ·
   `page.goBack/goReload` and navigation methods where they matter for auth redirects
   (HTTP Basic re-prompt) · anything else you find in the API docs.
4. **The matrix** — for each census row × each viable interposition point: ✅ / ⚠️ (works
   with caveats — list them) / ❌ (impossible — explain the physical/architectural reason),
   and **which threat tier the combination guarantees**. Every ⚠️/❌ needs a reason;
   use file:line or doc URLs as sources. Sensitive-data sub-classification where behavior
   differs: password vs OTP vs PII vs card number (e.g. client-side password hashing
   breaks network-layer injection; card data interacts with autofill differently).
5. **Baseline gaps** — where the current ZeroCreds/trained-assist-agent implementation
   stands (the leaks listed above), stated as facts with file:line.
6. **Verdict & recommendation** — which pattern(s) to make the default for safe-playwright
   (expected: separate login browser / server-side fill + storage-state handoff as the
   universal answer; network injection for API-style auth; MCP-layer interception as the
   T0-only cheap tier), what to forbid outright, and what canary/audit machinery is needed
   to satisfy the "audited code only" requirement. Be honest about what CDP makes
   impossible — if a tier cannot be guaranteed for a class of methods, say so plainly.

Style: engineering research, not marketing. Russian or English (pick one, be consistent).
Every strong claim needs a source (file:line in the input repos, or doc/URL). No fluff.

## Process (repo rules)

Repo: `~/Code/safe-playwright` (already cloned, `main` has bootstrap commit).

1. `git checkout -b research/sensitive-data-proxy-feasibility-checklist`
2. Write `docs/sensitive-data-proxy-feasibility-checklist.md`.
3. `git add`, commit with message `docs: sensitive-data proxy feasibility checklist — threat tiers, interposition points, data-entry census` and trailer:
   `Co-authored-by: opencode via MiMo V2.6-Flash <noreply@opencode.ai>`
4. `git push -u origin <branch>`
5. `gh pr create --repo Zerocreds-com/safe-playwright --title "docs: sensitive-data proxy feasibility checklist" --body "<summary + link to the doc + key verdicts>"`
6. `gh issue create --repo Zerocreds-com/safe-playwright --title "Implement safe-playwright proxy layer per feasibility checklist verdicts" --body "<what the checklist concluded + link to PR/doc; label=enhancement>"`
7. Update `checklist.md` goal line to reference the real PR number.

## Final report back

Return exactly: PR URL, issue URL, path of the doc, and a 5–10 line summary of the key
verdicts (which tiers are achievable for which interposition points; the recommended default).
