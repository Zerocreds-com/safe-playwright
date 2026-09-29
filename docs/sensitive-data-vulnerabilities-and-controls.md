# Sensitive-data vulnerabilities and controls

**Research doc for safe-playwright.** Where a proxy layer can be inserted so that a
Playwright-driven session can type sensitive data (password, OTP, PII, card, passport)
into a page while progressively stronger parties are kept from seeing it.

- Status: research complete, no implementation code in this PR
  ([PR #1](https://github.com/Zerocreds-com/safe-playwright/pull/1); tracking
  [issue #2](https://github.com/Zerocreds-com/safe-playwright/issues/2)).
- Inputs: prior research `playwright_история_безопасность_и_гранулярный_доступ.md`
  (external input file in `~/Downloads`, kept under its original name;
  "Playwright: history, security and granular access" —
  capability levels 0–5, prompt-injection vectors, Playwright Proxy Layer sketch —
  builds on it, does not repeat it), the `trained-assist-agent` codebase
  (ZeroCreds + Playwright usage, cited as `trained-assist-agent/<path>:<line>`),
  upstream docs (playwright.dev, `@playwright/mcp` v0.0.29 npm tarball,
  Chrome DevTools Protocol `browser_protocol.json`/`js_protocol.json`).
- Checked: 2026-09-28. Playwright docs current for v1.63.0; the repo's
  `@playwright/mcp@^0.0.29` resolves to exactly `0.0.29` (`^0.0.29` ⇒
  `>=0.0.29 <0.0.30`), which pins `playwright@1.53.0`.

---

## 0. What "the guarantee" means

ZeroCreds' claim is "the bot uses a password without seeing it": the password goes
browser → HTTP → `0600` file → short-lived handler → Playwright child env, and never
enters the LLM prompt / tool args / tool results. That is one tier (T0 below).

The user's operative requirement for safe-playwright, in full:

> Only audited code may see a credential, and its access must be reliably controlled —
> not only by build integrity (open source + protected/reproducible build), but e.g. by
> fake/canary credentials with availability alerts and audit logs.

This document answers: *where can a proxy layer physically interpose, and which of the
four "must not see" parties does each interposition actually guarantee?*

---

## 1. Threat model — 4 tiers + cross-cutting requirement

### 1.1 Tiers

| Tier | Who must NOT see the value | Concrete channels |
|---|---|---|
| **T0** | The LLM context | prompt text, tool **arguments**, tool **results** (incl. DOM snapshots, screenshots-as-tool-results, returned code blocks), any log the model can read back |
| **T1** | The Playwright driver process of the agent session | Node process memory (JS strings/buffers), child-process **env**, core dumps, `page.on('request')` → `request.postDataBuffer()` bodies, CDP traffic the driver itself subscribes to, driver-side temp files |
| **T2** | The page-side adversary | DOM read via `page.evaluate` / `locator.inputValue` / `Runtime.evaluate`, any CDP owner of that browser, page JS on a hostile or XSS'd site (`input`/`beforeinput` listeners, value trackers), screenshots / vision-model input (`Page.captureScreenshot`, `browser_screen_capture`) |
| **T3** | The network beyond the browser | forward/mitm proxies, TLS endpoints, server-side logs after the value leaves the browser, referrers, analytics beacons |

**Reading the matrix in §4.** Tiers listed in a cell are the tiers that
*row × interposition point* combination **guarantees**. Tiers not listed are not
guaranteed. Notation:

- `✅ T0 T1` — guaranteed for the listed tiers.
- `⚠ T0 · <reason>` — guaranteed only for the listed tier(s); the reason explains what
  is lost.
- `❌ <reason>` — the combination cannot work; reason is the physical/architectural cause.
- `–` — the point does not sit on this row's execution path; combining them has no
  effect and guarantees nothing (baseline: none). This is the global reason for every
  `–` cell; it is not repeated per cell.

**Where "T1"/"T2" point in cells.** T1 = *the agent-bearing driver*. T2 = *the agent-side
page / CDP / screenshot adversary*. A process that performs a fill becomes a T1-level
holder by construction (law L2) — cells list it as guaranteed only when that holder is
the audited filler, not the agent's driver.

### 1.2 Inherent laws (what no interposition point can change)

| Law | Statement | Consequence |
|---|---|---|
| **L1** | A value typed into a page is in the renderer's DOM. Page JS, `Runtime.evaluate`, `DOMSnapshot.inputValue` and `element.value` all read it. | **T2 cannot be guaranteed against the target page during the fill.** The site must receive the credential; that is the point of filling. T2 in cells therefore means *vs the agent-side adversary*. |
| **L2** | The process that types the value holds it in memory (keystrokes, `insertText` payload, evaluate argument, route `postData`). | **T1 cannot be guaranteed for the filling process itself.** It can only be moved from "the agent's driver" to "a minimal audited filler". |
| **L3** | Anything the model can see once, it has seen forever. | T0 must be enforced at *emission* time (reference-mode args) **and** at *return* time (snapshot/screenshot/code-echo redaction). One leak channel invalidates T0 permanently. |
| **L4** | Every TLS/proxy endpoint on the path sees T3-eligible bytes. | T3 guarantee = "the only parties who see it are inside the audited boundary". A mitm proxy is *in* the boundary, not a violation of it — but it becomes the highest-value target and must be canaried accordingly. |
| **L5** | If a value remains in the DOM after the fill (PII, card, uncleared password field), any later agent-side read re-breaches T2. | Post-fill hygiene (submit → navigation, `locator.clear()`, one-time values) is part of the guarantee, not an optional extra. |

### 1.3 Cross-cutting requirement: only audited code touches creds

Build integrity alone is necessary but insufficient — it says nothing about *runtime
access*. The control set that satisfies the user's operative requirement:

| Control | What it buys | Status in current code |
|---|---|---|
| Open source (this repo, MIT) | third parties can verify the fill path contains no exfiltration | ✅ repo public |
| Protected / reproducible build + pinned deps | the binary/JS that runs is the JS that was reviewed | ⚠️ not yet specified for safe-playwright |
| **Canary credentials** | *detection* of unaudited reads: plant fake creds in the same store; any **read** of a canary outside an authorized login attempt, and any **use** of a canary (login attempt from any network) is by construction unauthorized → alert | ❌ not implemented |
| **Access alerts / dead-man heartbeat** | silence is detectable: if the audit stream stops arriving for N minutes, page someone — an attacker who kills logging is caught by absence | ❌ not implemented |
| **Append-only audit log** (hash-chained, shipped off-box) | tamper-evident record of every credential access: who/what/when/which service | ⚠️ `.secrets_log` exists but is a local, mutable, un-chained file (see §5, gap 8) |
| Runtime hygiene of the filler | `ulimit -c 0` / disabled core dumps, no value in argv (argv is world-readable via `ps`/`/proc/*/cmdline`), scrubbed env after use, no stdout of values | ❌ not implemented |

Canary mechanics worth specifying up front:

1. **Read-canaries** — a canary entry in the credential store whose *only* legitimate
   reader is the audited fill path. File-access auditing (EDR / `fanotify` / `auditd`
   open-by-process events) on `~/agent-tokens/**` flags any opener outside the allowlist
   of audited binaries. This catches "some other tool grepped the token dir".
2. **Use-canaries** — canary accounts (e.g. `canary-<random>@…` with a honey password)
   registered on target sites with login alerts on. Any login attempt with them is
   unauthorized by construction → immediate third-party notification path that does not
   depend on our own logging staying alive.
3. **Availability alert** — the audit log ships to a sink we do not control the
   deletion of; missing-heartbeat ⇒ alert (catches log deletion, process kill, disk
   wipe).

---

### 1.4 Summary — what each point guarantees

| Point | T0 (LLM) | T1 (agent driver) | T2 (agent-side page/CDP/pixels) | T3 (network) | One-line verdict |
|---|---|---|---|---|---|
| **P1** call-layer interception | ✅ *ref-mode only* | ❌ | ❌ | ❌ | mandatory floor, not a solution |
| **P2** separate fill process | ✅ | ✅ | ⚠️ post-fill only (L5) | ❌ | mechanism inside P5 |
| **P3** in-page bridge | ✅ | ❌ | ❌ *worse* | ❌ | forbid for secrets |
| **P4** network proxy | ✅ | ✅ | ✅ header-borne / ❌ form-borne | ✅ iff proxy ∈ boundary | best guarantee where auth is header-borne |
| **P5** login browser + handoff | ✅ | ✅ | ✅ vs agent (credential) | ⚠️ storage-state file | **universal default** |
| **P6** OS-level input | ✅ | ⚠️ body-risk | ❌ | ❌ | niche; focus-miss leak mode |
| **P7** browser autofill/PM | ✅ | ⚠️ / ❌ if CDP-triggered | ❌ | — | convenience; card/address niche |
| **P8** in-driver `page.route` | ✅ | ❌ | ⚠️ header-only | ❌ | P4 without isolation; T1 lost |

`❌` in a tier column = that tier is **not** guaranteed by this point; the physical
reason is stated per point in §2 (P1–P8) and per row × point in §4.

---

## 2. Interposition points

Eight candidate places to insert a proxy layer, with the tiers each can guarantee,
what it costs, and how it fails.

### P1 — MCP-tool / harness call-layer interception

**Mechanism.** A wrapper sits in front of the MCP server or around the harness' Playwright
call sites. The model never emits the value: tool args carry a *reference*
(`cred://service/password`) which the audited wrapper resolves to the real value in JS
immediately before calling Playwright. Return paths (tool results, appended ARIA
snapshots, echoed "Ran Playwright code" blocks) are redacted by the same wrapper.

**Guarantees:** `T0 ✅ (reference-mode only)` · `T1 ❌` · `T2 ❌` · `T3 ❌`.
Value resolution happens in the driver/harness process (L2), and the value still goes
into the page (L1).

**If the model emits the raw value instead of a reference**, T0 is already broken at the
sampler the moment the token exists — interception can contain downstream spread (logs,
driver) but cannot un-see it. So P1's T0 claim *requires* reference-mode enforcement
(arg schema = reference format, reject raw-looking secrets).

**Cost:** low — one wrapper, no new processes. **Failure modes:** model invents a raw
value (needs schema validation + canary-shaped arg detection); echo paths that bypass
the wrapper — with `@playwright/mcp` the snapshot and the code block are appended *by
the MCP server itself* (`mcp/lib/context.js:136`, `:166`), so a wrapper must sit around
or inside the MCP server, not merely around the agent; harness code that fills without
crossing the wrapper (`page.evaluate` rows C1–C8, J3/J4).

### P2 — separate fill process attached over CDP

**Mechanism.** A minimal audited process (own Node runtime; no LLM; no model-facing
stdout; core dumps off) reads the `0600` credential file, attaches to the browser over
CDP (`chromium.connectOverCDP`), performs the fill, detaches. The agent's driver is
detached or never attached during the fill.

**Guarantees:** `T0 ✅` · `T1 ✅ for the agent-bearing driver` (filler is inside the
audited boundary — L2 satisfied *by moving* the holder) · `T2 ✅ vs agent after fill
only if L5 hygiene holds` (field cleared/submitted/expired; otherwise the agent can read
the value back after resuming) · `T2 ❌ vs target page during fill` (L1).

**Cost:** second process + ownership coordination over the CDP endpoint (exactly one
attached driver during fill; serialize sessions). **Failure modes:** both drivers
attached at once (agent reads during fill); value left in DOM after resume (L5);
core dump / `/proc/<pid>/environ` exposure in the filler; concurrent sessions racing on
the same browser.

### P3 — in-page bridge (`exposeBinding` / `addInitScript`)

**Mechanism.** Page JS calls a binding the driver exposed; the driver-side handler
fetches the value from the store and returns it into the page
(playwright.dev/docs/api/class-page#page-expose-binding).

**Guarantees:** `T0 ✅` (model triggers by name) · `T1 ❌` (handler loads the value in
the driver) · `T2 ❌ — and *worse* than typing`: the hostile page receives the raw value
directly, without needing a keylogger. `T3 ❌`.

**Cost:** near zero code. **Failure modes:** any origin can call an un-gated binding
(`exposeBinding` survives navigations); gating it by origin inside the driver is a new
access-control surface with its own states and bypasses; the page can stash the returned
value anywhere. **Verdict: strictly dominated by P2 for secrets** — legitimate only for
non-secret defaults (theme, locale).

### P4 — network-layer proxy (mitmproxy-style)

**Mechanism.** An outbound proxy adds/rewrites the credential at the network layer:
`Authorization: Bearer/Basic` headers, or request-body fields. Two sub-cases with
fundamentally different guarantees:

- **Header-borne secrets** (API keys, Basic/Bearer): the page never holds the value.
  `T0 ✅ T1 ✅ T2 ✅`, and `T3` holds only if TLS terminates *at* the proxy — i.e. the
  proxy is inside the audited boundary (L4). The alternative, CONNECT passthrough, means
  you cannot rewrite anything. There is no third option for HTTPS.
- **Body-borne form logins**: the page already computed/held the value before the proxy
  ever sees the request → `T2 ❌`, nothing gained. Worse, **client-side hashing breaks
  it**: if the page sends `hash(password)` or a challenge-response (Digest/SRP/HMAC with
  server nonce), the proxy cannot synthesize the right body without reimplementing the
  site's auth scheme — and for challenge-response it never sees the plaintext at all.

**Guarantees (header case):** `T0 ✅ T1 ✅ T2 ✅ · T3 = proxy in boundary`.
**Cost:** CA distribution for TLS interception, per-site rewrite rules, the proxy is now
the crown-jewel process (canary it, keep it minimal, no LLM, no shell). **Failure
modes:** client-side hashing/challenge auth (above); cert pinning in app-like pages;
HTTP/2 and WebSocket frames needing separate handling; rule drift as sites change.

### P5 — separate login browser + storage-state handoff  ← the universal answer

**Mechanism.** The *entire* auth flow (password, OTP, CAPTCHA via human-in-the-loop,
security questions) runs in a dedicated audited login browser: headless or on a private
display, **no pixel export**, no model attachment, driver = filler = same minimal
audited process. On success it exports
`browserContext.storageState()` (cookies + localStorage origins,
playwright.dev/docs/api/class-browsercontext#browser-context-storage-state) and the
agent's browser is launched with `--storage-state <file>` (0600, short TTL). The agent's
browser never contains the password at all.

**Guarantees:** `T0 ✅` · `T1 ✅ (agent driver)` · `T2 ✅ vs agent — the password is
never in the agent-side DOM, evaluate, snapshot, or CDP session` · `T2 ❌ during fill in
the login browser (L1)` · `T3 = normal TLS + the storage-state file on disk (0600)`.

**Residual (must be stated):** the *session cookie* is a bearer secret and does cross to
the agent's browser by design — T2 after handoff applies to the **credential**, not to
the session. Mitigations: short-lived sessions, re-login via P5 when they expire, don't
hand off refresh tokens the agent doesn't need.

**Cost:** architectural — per-site login flows maintained in the fill browser;
CAPTCHA/2FA need a channel to a human; two browser fleets instead of one. **Failure
modes:** agent navigates its browser back to the login page (must be URL-blocked);
step-up auth mid-session demands the password again (route back through P5, never
through the agent); storage-state file theft (0600 + short TTL + audit every read);
session fixation / cookie injection via `addCookies` paths.

### P6 — OS-level input (xdotool / ydotool on the persistent noVNC Chrome)

**Mechanism.** The value is typed as OS key events into the real Chrome window
(`--remote-debugging-port=9224` persistent profile, driven over noVNC). No Playwright
API is involved in the typing itself.

**Guarantees:** `T0 ✅` (nothing model-facing) · `T1 ⚠ — keystrokes never enter the
driver, but an attached Playwright driver can still obtain request bodies
(`request.postDataBuffer()`, playwright.dev/docs/api/class-request#request-post-data-buffer;
CDP `Network.requestWillBeSent.request.postData` carries them inline up to
`maxPostDataSize`)` · `T2 ❌` (page JS sees the keystrokes; any CDP owner — including
the agent's `connectOverCDP('http://127.0.0.1:9224')` session — can read the field
afterwards).

**Cost:** OS dependencies, Xvfb/focus management, no actionability feedback, coordinate
fragility. **Failure modes:** focus lands in the wrong window ⇒ the secret is typed into
an unrelated application (a *novel* leak mode this architecture introduces); IME/layout
mismatch corrupting the value; headless machines have no display to type into.

### P7 — browser password-manager / autofill

**Mechanism.** The credential lives in the Chrome profile (keychain/sync); the page's
focus + input events make Chrome offer it; the user-gesture (or
CDP `Autofill.trigger`, chromedevtools.github.io/devtools-protocol/tot/Autofill/) fills
card/address fields from browser-side storage.

**Guarantees:** `T0 ✅` (model never sees it) · `T1 ✅ when filled by browser UI ·
❌ when triggered via `Autofill.trigger` — the CDP command carries the card number
through the driver (L2)` · `T2 ❌` — autofill is by definition visible to page DOM/JS
(and to `inputValue`/snapshot read-back) · `T3` normal.

**Scope limits (verified against the protocol):** the `Autofill` domain has exactly
`enable`, `disable`, `trigger(fieldId, card? | address?)`, `setAddresses` — **credit-card
and address fields only**, no general value setter; the event
`Autofill.addressFormFilled` returns `filledFields[].value` — i.e. CDP *reads back* what
autofill wrote. OTP autofill (`autocomplete="one-time-code"`) is realistically
mobile/OS-level, not desktop Playwright. **Cost:** profile management; Playwright-driven
Chrome rarely offers PM UI at all (automation + no gesture ⇒ no offer, `gust`). **Failure
modes:** wrong saved account; page reads the value (L1); automation flags suppress the
offer; headless has no autofill UI.

### P8 — Playwright `page.route` request interception (in-driver)

**Mechanism.** The harness registers `page.route(...)` and injects/rewrites the secret
in `route.continue({postData, headers})` at send time
(playwright.dev/docs/api/class-route#route-continue).

**Guarantees:** `T0 ✅ (reference-mode)` · `T1 ❌ by construction — the route handler
runs inside the driver process; the bytes are in driver memory` · `T2 ✅ only for
header-injection where the page never held the value; ❌ for body rewrites of values the
page already typed` · `T3` normal.

**Cost:** zero (existing API). It is P4 minus process isolation. **Failure modes:**
forbidden headers — **`Cookie`, `Host`, `Content-Length` cannot be overridden on
`route.continue`; the override is silently ignored and the original header is sent**
(warning on playwright.dev/docs/api/class-route#route-continue); enabling routing
disables the HTTP cache; service workers bypass `page.route` unless
`serviceWorkers: 'block'` / `context.route` is used; rewrites are not carried over to
redirects; page JS and the route handler can race on the same field.

---

## 3. Census of data-entry methods

Every way a value can enter a page or a request in Playwright / `@playwright/mcp` 0.0.29
/ raw CDP / the trained-assist-agent harness. "Driver holds" = the value is a JS value
in the agent-bearing driver's memory at some point. Sources: playwright.dev docs
(checked 2026-09-28), the `@playwright/mcp@0.0.29` npm tarball (`lib/` sources),
`browser_protocol.json`/`js_protocol.json` (ChromeDevTools/devtools-protocol, browser
protocol 1.3), Playwright source at pinned tags, trained-assist-agent file:line.

### Group A — Playwright fill family

| ID | Method | How the value travels | Notes / sources |
|---|---|---|---|
| A1 | `locator.fill(value)` | select-all + focus → `injectedScript.fill()`; for text-like/`password`/textarea/contenteditable it returns `needsinput` → `keyboard.insertText` → **CDP `Input.insertText`** (renderer edit, native `input` event). Date-like types (`date`, `month`…): direct `input.value = v` + `input`/`change` events | source: playwright `packages/playwright-core/src/server/dom.ts` `_fill` (v1.55.0:581-605), `packages/injected/src/injectedScript.ts` `fill()` (v1.55.0:805-838) — **no `nativeInputValueSetter` in the fill path**; `password` ∈ fillable set; `file` throws `Input of type "file" cannot be filled`. playwright.dev/docs/api/class-locator#locator-fill |
| A2 | `page.fill(sel, v)` | deprecated wrapper → A1 | #page-fill |
| A3 | `frame.fill(sel, v)` | deprecated wrapper → A1 | #frame-fill |
| A4 | `locator.pressSequentially(text)` | per-char `keydown` / `keypress`+`input` / `keyup` | added v1.38; needed for keydown-driven masks, OTP digit boxes, autocomplete popups. Note: **there is no `locator.fillSequentially`** in the Playwright API — verified against the full Locator method list in the v1.63 docs (2026-09-28). #locator-press-sequentially |
| A5 | `locator.type` / `page.type` / `frame.type` | deprecated aliases → A4 | #locator-type |
| A6 | `locator.press(key)` / `page.press` | single keydown/keyup (Tab, Enter, arrows) | navigates multi-box OTP/2FA forms. #locator-press |
| A7 | `locator.clear()` / `fill('')` | focus + clear + `input` event | post-submit hygiene (law L5). #locator-clear |
| A8 | `locator.check/uncheck/setChecked` | implemented as `page.mouse.click` on element centre + re-check | toggles: consent, "show password" eye. #locator-set-checked |
| A9 | `locator.selectOption(values)` | option selection; fires `change` + `input` | fixed-choice PII (country, DOB parts). #locator-select-option |
| A10 | `locator.dispatchEvent(type, init)` | synthetic event, **carries no value** | pairs with value-set tricks; itself is not an entry path. #locator-dispatch-event |
| A11 | `locator.setInputFiles(files)` | writes file(s) into `<input type=file>`; `{name,mimeType,buffer}` buffers live in the driver | the entry path for **certificates, key files, identity docs**. #locator-set-input-files |
| A12 | `page.on('filechooser')` → `fileChooser.setFiles` | async chooser interception, same buffers | #page-event-file-chooser |
| A13 | `locator.drop({files, data})` | external drag-and-drop of files **or clipboard-like data** (`text/plain`, …) | **v1.60 — not available on the MCP-pinned `playwright@1.53.0`**. #locator-drop |
| A14 | `locator.click/dblclick/tap/hover/dragTo` | clicks that *select* a value already on screen: autofill dropdown item, OS SMS-OTP suggestion, "Paste" menu item, virtual keyboard key | value originates elsewhere (K1/K2/D2); click is the selector. #locator-click |

### Group B — keyboard / mouse primitives

| ID | Method | How the value travels | Notes / sources |
|---|---|---|---|
| B1 | `page.keyboard.type(text)` | keydown/keypress+input/keyup per char | #keyboard-type |
| B2 | `page.keyboard.insertText(text)` | **input event only** — no keydown/keyup/keypress; public equivalent of CDP `Input.insertText`; what A1 uses under the hood | #keyboard-insert-text |
| B3 | `page.keyboard.press/down/up(key)` | single keys incl. `Control+V` / `Meta+V` paste trigger | paste needs a prior clipboard write (D1/D2) or pre-existing clipboard (D3) |
| B4 | `page.mouse.move/click/down/up/wheel(x,y)` | coordinate input — virtual keyboards, autofill popups, menus | #mouse-click |
| B5 | `page.touchscreen.tap(x,y)` | touch input; throws unless context `hasTouch` | #touchscreen-tap |
| B6 | `locator.focus()` then B1/B2 | focus-then-insert pattern (raw CDP: `DOM.focus` + `Input.insertText`) | pairs with G1/G2 |

### Group C — `page.evaluate` family (driver-run JS in the page)

| ID | Method | How the value travels | Notes / sources |
|---|---|---|---|
| C1 | `page.evaluate` plain `el.value = v` | direct assignment in page JS; **no events fired** → framework state doesn't update | #page-evaluate |
| C2 | `page.evaluate` + `nativeInputValueSetter` + `input`/`change` dispatch | prototype setter trick for Vue/React controlled inputs | trained-assist-agent `src/nalog-login.js:181-189` |
| C3 | `page.evaluate` direct assignment + `input`/`change` dispatch | same family, simplest variant | `src/getcourse-login.js:68-76`, `src/tilda-login.js:80-86` |
| C4 | `page.evaluate` + `Object.defineProperty(HTMLInputElement.prototype,'value',…)` patch | React value-tracker variant of C2 | same mechanics; common in the wild |
| C5 | `locator.evaluate(el => …)` | element-scoped eval, same page-context power | #locator-evaluate |
| C6 | `$eval` / `$$eval` | deprecated wrappers → C5 | #page-eval |
| C7 | `page.evaluateHandle` + JSHandle property writes | value written via a handle, can avoid a *return* trip of the value to the driver | still driver-side write; page holds it |
| C8 | `page.evaluate(string)` — script as **string** | model-authored JS executed verbatim | the harness pattern: `browser_session_evaluate` (`EVAL_SCRIPT` env → `page.evaluate`), `ru_browser_fetch` → `src/ru-edge.js:389` |

### Group D — clipboard

| ID | Method | How the value travels | Notes / sources |
|---|---|---|---|
| D1 | `navigator.clipboard.writeText(v)` inside `page.evaluate` + B3 paste | needs `browserContext.grantPermissions(['clipboard-read','clipboard-write'])` | no dedicated Playwright clipboard API exists; #browser-context-grant-permissions |
| D2 | OS clipboard write outside the browser + B3 paste | value never enters the driver or the page JS — until the paste lands in the DOM | complements P6 |
| D3 | `page.keyboard.press('Control+V')` with whatever is already in the clipboard | provenance risk: pastes *foreign* secrets (previous user copy) into the page and possibly into the tool result | uncontrolled source |

### Group E — navigation / header & URL-borne credentials

| ID | Method | How the value travels | Notes / sources |
|---|---|---|---|
| E1 | `page.goto('https://user:pass@host/')` | credentials in the URL string → driver memory, server logs, possibly referrer/history | modern fetch/XHR reject userinfo URLs; treat as legacy-only. #page-goto |
| E2 | `page.setExtraHTTPHeaders({Authorization})` | header applied to **every request the page initiates**; value in driver + page config | #page-set-extra-http-headers |
| E3 | `browserContext.setHTTPCredentials({username,password})` | preemptive answer to HTTP Basic challenge; browser + driver hold the value | #browser-context-set-http-credentials |
| E4 | `browser.newContext({httpCredentials, extraHTTPHeaders, storageState})` | same at context construction; `storageState` is the P5 handoff input | #browser-new-context |
| E5 | `browserContext.addCookies([...])` | injects session cookies — **the handoff primitive of P5**; value = session token, not password | #browser-context-add-cookies |
| E6 | `page.goBack()`/`reload` re-triggering the **native HTTP-auth prompt** | ⚠️ **no Playwright API can fill it** — Chromium's HTTP-auth dialog is not a JS dialog, `page.on('dialog')` never fires for it (absent from the page-event list, #page-event-dialog is JS only) | therefore Basic auth must be preemptive (E3/E4) or P4-injected |
| E7 | `page.setContent(html)` / CDP `Page.setDocumentContent` | whole-document write incl. `value="…"` attributes and hidden form defaults | #page-set-content |

### Group F — network interception & driver-side HTTP

| ID | Method | How the value travels | Notes / sources |
|---|---|---|---|
| F1 | `page.route` + `route.continue({postData, headers})` | mid-flight rewrite in the driver process | forbidden headers (`Cookie`,`Host`,`Content-Length`) silently ignored; routing disables HTTP cache. #route-continue |
| F2 | `route.fallback(...)` | layered handler chain, same driver-side memory | #route-fallback |
| F3 | `route.fetch(...)` | **driver re-issues** the request with a modified body — value explicitly in driver | #route-fetch |
| F4 | `browserContext.route(...)` | context-wide variant of F1 (also reaches frames/workers better) | #browser-context-route; pair with `serviceWorkers:'block'` |
| F5 | `route.fulfill({...})` | response-side mock; can fake post-auth responses, **cannot set cookies directly** | #route-fulfill |
| F6 | `page.routeFromHAR(har)` | replays requests from a HAR — secrets live in the HAR file on disk | #route-from-har |
| F7 | `page.routeWebSocket(url, handler)` | rewrites WS frames — auth tokens commonly travel in WS messages | #page-route-web-socket |
| F8 | `page.request` / `APIRequestContext.post(...)` | HTTP issued **by the driver**, shares context cookies, never touches the page DOM | the clean path for API-style auth. #api-request-context-post |
| F9 | `page.on('request')` → `request.postDataBuffer()` | **read-back**: any driver can recover request bodies it sent/received | #request-post-data-buffer; CDP: `Network.requestWillBeSent.request.postData`, `Network.getRequestPostData` |

### Group G — raw CDP (via `browserContext.newCDPSession`, Chromium only)

| ID | Method | How the value travels | Notes / sources |
|---|---|---|---|
| G1 | `Input.insertText(text)` | same primitive A1/B2 use | protocol marks it experimental-flagged; source: `browser_protocol.json` Input domain |
| G2 | `Input.dispatchKeyEvent(type:'keyDown'\|'char', text, …)` | per-char with explicit text payload | enum verified in `browser_protocol.json` |
| G3 | `Runtime.evaluate(expr, returnByValue)` / `Runtime.callFunctionOn` | generic value write **and read** (`el.value`) in page context | `js_protocol.json` Runtime domain |
| G4 | `Page.addScriptToEvaluateOnNewDocument(source)` | runs before the page's own scripts — can seed values before frameworks init | `browser_protocol.json` Page domain |
| G5 | `DOM.setFileInputFiles(files, …)` | **the one direct setter CDP has** — `<input type=file>` only | no general "set input value": `DOM.setNodeValue` on an `<input>` errors `Can only set value of text nodes` (github.com/ChromeDevTools/devtools-protocol/issues/32); `DOM.setAttributeValue('value')` writes `defaultValue` only and is wiped on re-render |
| G6 | `DOMStorage.setDOMStorageItem(storageId, key, value)` | direct `localStorage` write (session-token injection without page JS) | DOMStorage domain |
| G7 | `Network.setExtraHTTPHeaders` / `Fetch.continueRequest({headers, postData})` | CDP-level network injection (out-of-page) | `Fetch.requestPaused` ⇒ `continueRequest(postData)`; note driver holds bytes (L2) |
| G8 | `Autofill.trigger({card?, address?})` (+`Autofill.setAddresses`) | browser's own autofill fills card/address fields; **card number travels in the CDP command** | only 4 commands exist in the domain; `addressFormFilled.filledFields[].value` reads back what was filled |
| G9 | `Page.handleJavaScriptDialog(accept, promptText)` | answers `prompt()` dialogs — a page can *ask* for data through it | also the shape of MCP `browser_handle_dialog` |
| G10 | `Target.exposeDevToolsProtocol(targetId, binding)` | **anti-pattern**: hands a raw CDP channel to page JS | never expose this to a page that receives secrets |
| G11 | `DOM.setNodeValue(nodeId, v)` on an input | ❌ **fails by design** — errors `Can only set value of text nodes`; proves CDP has no direct value setter | issues/32 above; included as the negative control row |

### Group H — page-side config bridges

| ID | Method | How the value travels | Notes / sources |
|---|---|---|---|
| H1 | `page.addInitScript(fn\|{path,content})` | Playwright-API twin of G4; runs after document creation, before page scripts | #page-add-init-script |
| H2 | `page.exposeBinding(name, cb)` / `exposeFunction` | page pulls a value from the driver-side store on demand | binding survives navigations → origin-gating needed. #page-expose-binding |
| H3 | CDP `Runtime.addBinding(name)` | same bridge, CDP-native; `Runtime.bindingCalled` event carries the page's request | js_protocol.json |

### Group I — `@playwright/mcp` 0.0.29 tool surface

Source: npm tarball `@playwright/mcp@0.0.29` (`package/lib/tools/*.js`,
`package/lib/context.js`; tag `v0.0.29` = `0df6d7a` on microsoft/playwright-mcp).
Snapshot mode exposes 25 tools, vision mode 23; capability gating in
`lib/connection.js:24`.

| ID | Tool | How the value travels | Notes / sources (tarball paths) |
|---|---|---|---|
| I1 | `browser_type({element, ref, text, submit?, slowly?})` | `text: z.string()` **as a tool argument** (T0 at emission); default → `locator.fill`, `slowly` → `pressSequentially` | `lib/tools/snapshot.js:122-157`; **echoes the text back twice**: in the returned code block `// Fill "${params.text}"…` (`snapshot.js:145`) rendered by `lib/context.js:136`, and again via the appended ARIA snapshot |
| I2 | `browser_press_key({key})` | `keyboard.press` | `lib/tools/keyboard.js` |
| I3 | `browser_select_option({element, ref, values[]})` | `locator.selectOption` | `lib/tools/snapshot.js` |
| I4 | `browser_click({element, ref})` | click that can *select* autofill/paste suggestions (A14) | `lib/tools/snapshot.js` |
| I5 | `browser_file_upload({paths[]})` | absolute **paths** (not buffers) applied to an **already-open** file chooser — throws `No file chooser visible` otherwise | `lib/tools/files.js:18-48`, `:32` |
| I6 | `browser_navigate({url})` | URL string → E1 concerns | `lib/tools/navigate.js` |
| I7 | `browser_screen_type({text})` (vision mode) | `page.keyboard.type(text)` — value in tool args + driver | `lib/tools/vision.js:164,167` |
| I8 | `browser_handle_dialog({accept, promptText?})` | dialog answer as tool arg (G9) | `lib/tools/dialogs.js` |
| I9 | `browser_snapshot` (+ snapshot appended to **every** mutating result) | **read-back of input values incl. `type=password`**: Playwright's ARIA snapshot stores `result.children = [element.value]` for every input except checkbox/radio/file, with **no `password` branch** | playwright `packages/injected/src/ariaSnapshot.ts:216-218` @ **v1.53.0** (grep `password` → 0 hits); chain `packages/playwright-core/src/server/page.ts:992-1008` → mcp `lib/pageSnapshot.js:32` → appended at `lib/context.js:166`. **This is the single biggest T0 hole in the pinned stack.** |
| I10 | `browser_network_requests` | metadata only (`[METHOD] url => [status]`), **no bodies** | `lib/network.js` `renderRequest` — no leak |
| I11 | `browser_take_screenshot` / `browser_screen_capture` | pixels → vision tier (T2): password fields render as dots, **OTP/PII/card numbers render as themselves** | `lib/tools/screenshot.js:63-70`, `lib/tools/vision.js:39-42` |
| I12 | `browser_generate_playwright_test({name, description, steps[]})` | returns an instruction blob; **does not execute code** | `lib/tools/testing.js:26-46` |
| I13 | *(absence)* no `browser_evaluate`, no `browser_fill_form` | — | grep over `lib/` in 0.0.29: the only `evaluate` hits are internal (`context.js:184`) — the MCP surface itself has **no model-JS execution tool**; the escape hatch only exists in the host harness (C8, J3/J4) |
| I14 | `browser_console_messages` | read-back: a `console.log(password)` anywhere leaks to the model | `lib/tools/console.js` |

### Group J — trained-assist-agent harness surfaces

| ID | Surface | How the value travels | Sources |
|---|---|---|---|
| J1 | `browser_session_login({email, password})` | **password as LLM tool args** → child env `LOGIN_EMAIL`/`LOGIN_PASSWORD` | `trained-assist-agent/src/mcp-skills/tools/21-browser-session.js:303-338` (schema `:309`, env `:321`) |
| J2 | `browser_session_autologin({service})` | MCP handler reads `~/agent-tokens/<uid>/<svc>` **itself**, passes to child via env — *password never in LLM context* (the ZeroCreds pattern) | `21-browser-session.js:248-299` (file `:252`, env `:272`); child `infra/browser-session/login.js` (env read `:8-14`, `connectOverCDP('http://127.0.0.1:9224')` `:18`) |
| J3 | `browser_session_evaluate({script})` | model-authored JS → `EVAL_SCRIPT` env → `execSync(node evaluate.js)` → `page.evaluate` | `21-browser-session.js:127-168` (`:154`) |
| J4 | `ru_browser_fetch({url, script})` | model JS → HTTP `POST /playwright-fetch` to the RU VM → `page.evaluate(script)` | `src/mcp-skills/tools/22-ru-browser.js:12,25-47` → `src/ru-edge.js:389` |
| J5 | `browser_session_capture_cookies({domain})` | **raw cookie string returned as tool result** (and written to the token dir) | `21-browser-session.js:170-222` (`output` at `:216`) |
| J6 | `loadUserTokens(userId)` catch-all | any credential file not specially handled is injected **as-is into the engine env** under `<LABEL>` | `src/user-tokens.js:132` (fn), `:225` (catch-all), return `:228` |
| J7 | OS-level input on the persistent noVNC Chrome | **not implemented in the repo** — prospective P6 row (xdotool etc. against the `:9224` Chrome) | — |
| J8 | `@playwright/mcp` mounted in every engine session with `--storage-state <file>` | all session cookies in one driver-readable file; MCP snapshot stack of I9 active in every session | `src/browser.js:126-131`; `@playwright/mcp` pin `package.json:27` |

### Group K — browser-native autofill, heuristics, structural variants

| ID | Surface | How the value travels | Notes / sources |
|---|---|---|---|
| K1 | Chrome profile password-manager autofill | focus + input events → Chrome offers saved creds → user-gesture fill → value in DOM (L1) | unreliable under automation (no gesture, automation flags); see P7 |
| K2 | `autocomplete` heuristics incl. `autocomplete="one-time-code"` | OS/browser OTP autofill (mostly mobile); desktop Playwright rarely gets it | value lands in DOM like any fill |
| K3 | Shadow DOM piercing | Playwright selector engines pierce **open** shadow roots transparently (A1 chain unchanged); closed roots and `page.evaluate` need manual traversal | same guarantees as the underlying row; only reachability changes |
| K4 | Frames: `frameLocator(...).locator.fill` | same chain inside iframes (incl. cross-origin — Playwright reaches them) | #frame-locator; guarantees unchanged |
| K5 | contenteditable / rich editors (Lexical, ProseMirror, TinyMCE) | A1 supports contenteditable, but editors that ignore `Input.insertText` need A4 key-simulation | ⚠️ editors vary: `fill` may produce a visually empty editor |

---

## 4. The matrix

### 4.0 Reading guide

Columns = interposition points P1–P8 (§2). Rows = census IDs (§3). Cell = tiers
guaranteed + reason for every `⚠`/`❌`. Global `–` reason: point not on this row's path.
Reminder of the two substitution columns: under **P4** the row's value is *not* passed by
this row — it is added at the network layer instead; under **P6/P7** the row's typing is
*replaced* by OS input / browser autofill. "T2" always = agent-side; the target page
sees the value during any fill (L1), except header-borne P4 injection where the page
never holds it. `T2a` in a cell abbreviates "T2 guaranteed **against the agent-side
adversary only** — never against the target page itself (law L1)"; `T1✗` abbreviates
"tier explicitly not guaranteed, reason follows".

### 4.1 Group A — fill family

| ID | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---|---|---|---|---|---|---|---|
| A1 `locator.fill` | ⚠ T0 · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds value | ✅ T0 T1 T2a | ⚠ T0 · T1 body-risk, focus | ⚠ T0 T1 · pg-sees, gust | ❌ no-gain · pg already holds |
| A2 `page.fill` | ⚠ T0 · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds value | ✅ T0 T1 T2a | ⚠ T0 · T1 body-risk, focus | ⚠ T0 T1 · pg-sees, gust | ❌ no-gain · pg already holds |
| A3 `frame.fill` | ⚠ T0 · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds value | ✅ T0 T1 T2a | ⚠ T0 · T1 body-risk, focus | ⚠ T0 T1 · pg-sees, gust | ❌ no-gain · pg already holds |
| A4 `pressSequentially` | ⚠ T0 · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds value | ✅ T0 T1 T2a | ⚠ T0 · T1 body-risk, focus | ⚠ T0 T1 · pg-sees, gust | ❌ no-gain · pg already holds |
| A5 `type` (deprecated) | ⚠ T0 · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds value | ✅ T0 T1 T2a | ⚠ T0 · T1 body-risk, focus | ⚠ T0 T1 · pg-sees, gust | ❌ no-gain · pg already holds |
| A6 `press(key)` | ⚠ T0 · no secret in arg | ✅ T0 T1 T2a | – | – | ✅ T0 T1 T2a | ✅ T0 T1 · focus only | ✅ T0 T1 T2a | – |
| A7 `clear()` | ✅ T0 · removal only | ✅ T0 T1 T2a | – | – | ✅ T0 T1 T2a | ✅ T0 T1 | ✅ T0 T1 | – |
| A8 `check/setChecked` | ✅ T0 · boolean | ✅ T0 T1 T2a | – | – | ✅ T0 T1 T2a | ✅ T0 T1 · focus | ✅ T0 T1 T2a | – |
| A9 `selectOption` | ✅ T0(ref) · fixed set | ✅ T0 T1 T2a | – | – | ✅ T0 T1 T2a | ⚠ T0 · focus, no key-equiv | ✅ T0 T1 T2a | – |
| A10 `dispatchEvent` | ✅ T0 · no value | ✅ T0 T1 T2a | – | – | ✅ T0 T1 T2a | ✅ T0 T1 | ✅ T0 T1 | – |
| A11 `setInputFiles` | ⚠ T0(ref) · drv holds buffer | ⚠ T0 T1 · filler reads file (L2); T2 file-bytes | ❌ pg gets file, not ref | ❌ multipart built by browser | ⚠ T0 T1 T2a · file bytes in fill-bw | ❌ no OS-typing path | ❌ PM stores forms not files | ❌ drv holds buffer |
| A12 `filechooser.setFiles` | ⚠ T0(ref) · drv holds buffer | ⚠ T0 T1 · filler reads file (L2) | ❌ same as A11 | ❌ same as A11 | ⚠ T0 T1 T2a · file in fill-bw | ❌ chooser needs driver event | ❌ PM stores forms not files | ❌ drv holds buffer |
| A13 `locator.drop` | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 · **ver: needs pw≥1.60** | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a · ver: pw≥1.60 | ✅ T0 T1 · focus | ❌ drop payload not PM data | ❌ no-gain |
| A14 click-selects-value | ⚠ T0 · selection not value | ✅ T0 T1 T2a | – | – | ✅ T0 T1 T2a | ✅ T0 T1 · focus | ✅ T0 T1 T2a · this *is* PM flow | – |

### 4.2 Group B — keyboard / mouse

| ID | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---|---|---|---|---|---|---|---|
| B1 `keyboard.type` | ⚠ T0 · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | ✅ T0 T1 · pg-sees (T2✗ by L1) | ⚠ T0 T1 · pg-sees, gust | ❌ no-gain · pg already holds |
| B2 `keyboard.insertText` | ⚠ T0 · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | ✅ T0 T1 · pg-sees | ⚠ T0 T1 · pg-sees, gust | ❌ no-gain · pg already holds |
| B3 `press(Ctrl+V)` | ⚠ T0 · clipboard provenance | ✅ T0 T1 T2a · if D2 seeded | – | – | ✅ T0 T1 T2a | ✅ T0 T1 · OS clipboard ∈ boundary | ⚠ T0 T1 · PM writes clipboard too | – |
| B4 `mouse.click(x,y)` | ✅ T0 · coords only | ✅ T0 T1 T2a | – | – | ✅ T0 T1 T2a | ✅ T0 T1 · focus | ✅ T0 T1 T2a | – |
| B5 `touchscreen.tap` | ✅ T0 · coords only | ✅ T0 T1 T2a | – | – | ✅ T0 T1 T2a | ✅ T0 T1 · focus | ✅ T0 T1 T2a | – |
| B6 focus+insert | ⚠ T0 · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | ✅ T0 T1 · pg-sees | ⚠ T0 T1 · gust | ❌ no-gain |

### 4.3 Group C — evaluate family

| ID | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---|---|---|---|---|---|---|---|
| C1 plain `el.value=` | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | – row is JS, not keystrokes | ❌ PM not invoked by eval | ❌ no-gain |
| C2 nativeInputValueSetter | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | – | ❌ PM not invoked by eval | ❌ no-gain |
| C3 assign+events | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | – | ❌ PM not invoked by eval | ❌ no-gain |
| C4 defineProperty patch | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | – | ❌ PM not invoked by eval | ❌ no-gain |
| C5 `locator.evaluate` | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | – | ❌ PM not invoked by eval | ❌ no-gain |
| C6 `$eval`/`$$eval` | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | – | ❌ PM not invoked by eval | ❌ no-gain |
| C7 `evaluateHandle` writes | ⚠ T0(ref) · drv+pg (no return trip) | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | – | ❌ PM not invoked by eval | ❌ no-gain |
| C8 model-JS string eval | ⚠ T0 · **model authors the script — can read anything** | ✅ T0 T1 · T2 needs L5, script still in filler | ⚠ T0 · pg holds raw | ❌ script is page-side | ✅ T0 T1 T2a · run only in fill-bw | ❌ script still model-authored | ❌ PM not invoked by model JS | ❌ no-gain |

> C8 note: reference-mode P1 cannot make arbitrary model-authored JS safe — the script
> itself is an exfiltration channel (`return document.querySelector('#pw').value`).
> The only fixes: forbid C8 on pages that ever hold secrets, or replace it with an
> allowlist of audited RPC snippets (see §6 "forbid").

### 4.4 Group D — clipboard

| ID | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---|---|---|---|---|---|---|---|
| D1 `clipboard.writeText`+paste | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | ✅ T0 T1 · OS clipboard ∈ boundary, pg-sees | ⚠ T0 T1 · gust | ❌ no-gain |
| D2 OS clipboard + paste | ⚠ T0(ref) · outside drv | ✅ T0 T1 · T2 needs L5 | – | ❌ pg already holds | ✅ T0 T1 T2a | ✅ T0 T1 T2 · **the P6 flagship case** (value never in driver; pg-sees by L1) | ✅ T0 T1 · PM-to-clipboard variant | ❌ no-gain |
| D3 blind `Ctrl+V` | ❌ uncontrolled source · may paste foreign secret | ✅ T0 T1 T2a · only if clipboard pre-seeded audited | – | – | ✅ T0 T1 T2a | ✅ T0 T1 | ✅ T0 T1 | – |

### 4.5 Group E — navigation / header & URL credentials

| ID | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---|---|---|---|---|---|---|---|
| E1 creds-in-URL | ⚠ T0(ref) · drv+server-log | – P2 fills forms, not URLs | – | ⚠ T0 T1 T2 · proxy adds header instead, URL clean | ✅ T0 T1 T2a · URL only inside fill-bw | ⚠ T0 · driver navigates w/ URL | – | ❌ drv still holds URL creds |
| E2 `setExtraHTTPHeaders` | ⚠ T0(ref) · drv holds header | – header set at config, not fill | – | ✅ **T0 T1 T2** · proxy adds header; page+driver never hold · T3: proxy ∈ boundary | ✅ T0 T1 T2a · header config lives in fill-bw | – | – | ⚠ T0 · T1✗ drv, no isolation |
| E3 `setHTTPCredentials` | ⚠ T0(ref) · drv holds pwd | – | – | ✅ **T0 T1 T2** · proxy answers Basic preemptively | ✅ T0 T1 T2a · filler holds it (L2) | – | ⚠ T0 T1 · Chrome HTTP-auth storage, gust | ⚠ T0 T1 · drv holds pwd |
| E4 `newContext(httpCredentials,…)` | ⚠ T0(ref) · drv holds pwd | – | – | ✅ **T0 T1 T2** (same as E3) | ✅ T0 T1 T2a | – | ⚠ T0 T1 · gust | ⚠ T0 T1 · drv holds pwd |
| E5 `addCookies` (handoff) | ✅ T0 · session not cred | – | – | – | ✅ **T0 T1 T2a** · the handoff itself; residual = session token | – | – | – |
| E6 native HTTP-auth re-prompt | ❌ no API to fill prompt | ❌ no API in filler either | – | ✅ T0 T1 T2 · preemptive proxy header avoids prompt | ✅ T0 T1 T2a · solve with preemptive E3/E4 in fill-bw | ❌ OS keys don't reach browser-auth dialog | ❌ PM cannot answer native dialog | ❌ no Playwright API in driver |
| E7 `setContent` | ⚠ T0(ref) · drv+pg | ✅ T0 T1 T2a · runs in fill-bw | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | – | ❌ PM not invoked | ❌ no-gain |

### 4.6 Group F — network interception & driver-side HTTP

| ID | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---|---|---|---|---|---|---|---|
| F1 `route.continue(postData)` | ⚠ T0(ref) · **drv holds bytes** | – P2 doesn't move route handlers | – | ✅ **T0 T1 T2** · do it out-of-process instead | – agent-side route | – | – | ⚠ T0 · T1✗ drv-inherent; forbidden Cookie/Host headers ignored |
| F2 `route.fallback` | ⚠ T0(ref) · drv holds bytes | – | – | ✅ T0 T1 T2 · out-of-process | – | – | – | ⚠ T0 · T1✗ drv-inherent |
| F3 `route.fetch` | ⚠ T0(ref) · drv holds bytes | – | – | ✅ T0 T1 T2 · out-of-process | – | – | – | ⚠ T0 · T1✗ drv re-issues request |
| F4 `context.route` | ⚠ T0(ref) · drv holds bytes | – | – | ✅ T0 T1 T2 · out-of-process | – | – | – | ⚠ T0 · T1✗ |
| F5 `route.fulfill` | ✅ T0 · response-side | – | – | ✅ T0 T1 T2 · response mock | – | – | – | ⚠ T0 · T1✗ but no secret enters |
| F6 `routeFromHAR` | ❌ secrets-on-disk in HAR | ❌ HAR readable by filler too | – | ❌ replay, no injection point | ✅ T0 T1 T2a · HAR only in fill-bw | ❌ replay is not typing | ❌ not a fill path | ❌ HAR in driver cwd |
| F7 `routeWebSocket` | ⚠ T0(ref) · drv holds frames | – | – | ✅ T0 T1 T2 · proxy rewrites WS after TLS-termination | – | – | – | ⚠ T0 · T1✗ |
| F8 `APIRequestContext.post` | ⚠ T0(ref) · drv holds body | – | – | ✅ **T0 T1 T2** · driver sends clean request, proxy injects auth header | ✅ T0 T1 T2a · issue it from filler | – | – | ⚠ T0 · T1✗ |
| F9 `request.postDataBuffer` (read-back) | ✅ T0 · redact at wrapper | ✅ T0 T1 T2a · agent driver never sees fill-bw traffic | – | ✅ T0 T1 T2 | ✅ T0 T1 T2a | ⚠ T0 T1✗ · attached drv still observes bodies | – | ⚠ T0 T1✗ · handler lives in drv |

### 4.7 Group G — raw CDP

| ID | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---|---|---|---|---|---|---|---|
| G1 `Input.insertText` | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | ✅ T0 T1 · pg-sees | ⚠ T0 T1 · gust | ❌ no-gain |
| G2 `Input.dispatchKeyEvent` | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | ✅ T0 T1 · pg-sees | ⚠ T0 T1 · gust | ❌ no-gain |
| G3 `Runtime.evaluate` | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | – | ❌ PM not invoked by eval | ❌ no-gain |
| G4 `addScriptToEvaluateOnNewDocument` | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw before its own JS runs | ❌ pg already holds | ✅ T0 T1 T2a | – | ❌ PM not invoked by init script | ❌ no-gain |
| G5 `DOM.setFileInputFiles` | ⚠ T0(ref) · drv holds paths | ⚠ T0 T1 · filler reads file (L2) | ❌ pg gets file, not ref | ❌ multipart browser-built | ⚠ T0 T1 T2a · file in fill-bw | ❌ no OS-typing path | ❌ PM stores forms not files | ❌ drv holds paths |
| G6 `DOMStorage.setDOMStorageItem` | ⚠ T0(ref) · drv holds value | ✅ T0 T1 · T2 token-in-DOM (L5: it's a token by design) | ⚠ T0 · pg JS reads storage | ✅ T0 T1 T2 · **bypass page JS entirely** for token injection | ✅ T0 T1 T2a · filler writes only | – | – | ⚠ T0 T1✗ |
| G7 `Fetch.continueRequest` / `Network.setExtraHTTPHeaders` | ⚠ T0(ref) · drv holds bytes | – | – | ✅ **T0 T1 T2** · move to out-of-process proxy | ✅ T0 T1 T2a if issued from filler | – | – | ⚠ T0 · T1✗ same as P8 |
| G8 `Autofill.trigger(card)` | ⚠ T0(ref) · **command carries card № through drv** | ⚠ T0 T1 · filler sends card (L2) | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a · card only in fill-bw | ⚠ T0 T1✗ · focus + cmd path | ✅ T0 T1 · **this column's native mechanism**; T2✗ pg-sees | ⚠ T0 T1✗ |
| G9 `handleJavaScriptDialog(promptText)` | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg asks page-side | ✅ T0 T1 T2a | ✅ T0 T1 · focus | ⚠ T0 T1 · gust | ❌ no-gain · dialog answer is page-side |
| G10 `Target.exposeDevToolsProtocol` | ❌ hands CDP to page JS | ❌ same in filler | ❌ this *is* P3's nuclear form | ❌ hands page CDP anyway | ❌ never in fill-bw | ❌ unrelated to typing | ❌ unrelated to typing | ❌ hands page CDP anyway |
| G11 `DOM.setNodeValue` on input | ❌ protocol rejects it (`Can only set value of text nodes`, issues/32) | ❌ same | ❌ protocol rejects value writes | ❌ protocol rejects value writes | ❌ protocol rejects value writes | ❌ protocol rejects value writes | ❌ protocol rejects value writes | ❌ protocol rejects value writes |

### 4.8 Group H — page-side bridges

| ID | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---|---|---|---|---|---|---|---|
| H1 `addInitScript` | ⚠ T0(ref) · script text in drv | ✅ T0 T1 · T2 needs L5 | ✅ T0 T1✗+T2✗ · bridge is the point of P3 | ❌ pg already holds | ✅ T0 T1 T2a | – | ❌ PM not invoked | – |
| H2 `exposeBinding` | ⚠ T0(ref) · handler in drv | ⚠ T0 T1✗ · handler loads value in driver | ⚠ T0 · **pg receives raw — P3's flaw** | ❌ pg receives raw · proxy adds nothing | ⚠ T0 T1 T2a · only if binding exists solely in fill-bw | – | ❌ PM not invoked by binding | – |
| H3 `Runtime.addBinding` | ⚠ T0(ref) · handler in drv | ⚠ T0 T1✗ | ⚠ T0 · pg receives raw | ❌ pg receives raw · proxy adds nothing | ⚠ T0 T1 T2a · fill-bw only | – | ❌ PM not invoked by binding | – |

### 4.9 Group I — `@playwright/mcp` 0.0.29 tools

| ID | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---|---|---|---|---|---|---|---|
| I1 `browser_type` | ⚠ **T0(ref) only — raw `text` arg is a T0 breach at emission, and the tool echoes it back in the code block (`context.js:136`) + appended snapshot** | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a · point MCP at fill-bw | ⚠ T0 · T1 body-risk | ⚠ T0 T1 · gust | ❌ no-gain |
| I2 `browser_press_key` | ✅ T0 · key name only | ✅ T0 T1 T2a | – | – | ✅ T0 T1 T2a | ✅ T0 T1 · focus | ✅ T0 T1 T2a | – |
| I3 `browser_select_option` | ✅ T0(ref) · fixed set | ✅ T0 T1 T2a | – | – | ✅ T0 T1 T2a | ⚠ T0 · no key path | ✅ T0 T1 T2a | – |
| I4 `browser_click` | ✅ T0 · selection not value | ✅ T0 T1 T2a | – | – | ✅ T0 T1 T2a | ✅ T0 T1 · focus | ✅ T0 T1 T2a · PM suggestion | – |
| I5 `browser_file_upload` | ⚠ T0(ref) · drv holds paths | ⚠ T0 T1 · filler reads file (L2) | ❌ pg gets file, not ref | ❌ multipart browser-built | ⚠ T0 T1 T2a · file in fill-bw | ❌ no OS-typing path | ❌ PM stores forms not files | ❌ drv holds paths |
| I6 `browser_navigate` | ⚠ T0(ref) · URL in drv | ✅ T0 T1 T2a | – | ✅ T0 T1 T2 · clean URL + proxy header | ✅ T0 T1 T2a | ⚠ T0 · drv holds URL | – | ❌ URL still in driver |
| I7 `browser_screen_type` | ⚠ T0(ref) · raw arg + echo | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | ✅ T0 T1 · pg-sees | ⚠ T0 T1 · gust | ❌ no-gain |
| I8 `browser_handle_dialog` | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ dialog answer is page-side | ✅ T0 T1 T2a | ✅ T0 T1 · focus | ⚠ T0 T1 · gust | – |
| I9 `browser_snapshot` (read-back) | ✅ **T0 · redact `children` of password/OTP inputs at wrapper** | ✅ T0 T1 T2a · snapshot taken only in fill-bw, agent gets state file | – | ✅ T0 T1 T2 · nothing in agent DOM to snapshot | ✅ T0 T1 T2a | ⚠ T0 T1✗ · attached drv can snapshot | ⚠ T0 T1✗ · attached drv can snapshot | ⚠ T0 T1✗ |
| I10 `browser_network_requests` | ✅ T0 · metadata only, no bodies | ✅ T0 T1 T2a | – | ✅ T0 T1 T2 | ✅ T0 T1 T2a | ✅ T0 T1 · no bodies | ✅ T0 T1 | ✅ T0 T1 · no bodies in listing |
| I11 `browser_take_screenshot`/`screen_capture` | ⚠ T0 · **redaction required — OTP/PII/card render legibly** | ✅ T0 T1 T2a · no pixel export from fill-bw | – | ✅ T0 T1 T2 · header-borne ⇒ nothing to see | ✅ T0 T1 T2a · **forbid screenshots in fill-bw** | ❌ px from agent drv shows typed value | ❌ px show autofilled value | ⚠ T0 T1✗ · px in drv |
| I12 `browser_generate_playwright_test` | ✅ T0 · no execution | ✅ T0 T1 T2a | – | – | ✅ T0 T1 T2a | ✅ T0 T1 | ✅ T0 T1 | – |
| I13 *(no `browser_evaluate`)* | ✅ T0 · surface absent | ✅ T0 T1 T2a | – | – | ✅ T0 T1 T2a | ✅ T0 T1 | ✅ T0 T1 | – |
| I14 `browser_console_messages` | ✅ T0 · redact at wrapper | ✅ T0 T1 T2a · console of fill-bw not exported | – | ✅ T0 T1 T2 | ✅ T0 T1 T2a | ⚠ T0 T1✗ · attached drv reads console | ⚠ T0 T1✗ | ⚠ T0 T1✗ |

### 4.10 Group J — harness surfaces

| ID | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---|---|---|---|---|---|---|---|
| J1 `browser_session_login` (pwd in args) | ⚠ **T0(ref) — requires changing the schema to a reference; with raw args T0 already broken** | ✅ T0 T1 · replace args with file lookup in handler | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ **T0 T1 T2a** — the target design: handler ⇒ fill-bw, no args | ⚠ T0 · T1 body-risk | ⚠ T0 T1 · gust | ❌ no-gain |
| J2 `browser_session_autologin` (ZeroCreds pattern) | ✅ **T0 already** — no secret in args | ✅ T0 T1 · child env ⇒ move cred loading *into* the filler (env is world-same-uid readable, core-dump prone) | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ **T0 T1 T2a** · current file+env flow *is* P5-lite; complete it by isolating the browser | ⚠ T0 · T1 body-risk | ⚠ T0 T1 · gust | ❌ no-gain |
| J3 `browser_session_evaluate` | ✅ **T0 · redact return values only if script is audited — model-authored script can echo secrets (§4.3 C8)** | ✅ T0 T1 T2a · run only in fill-bw | ❌ script runs in page | ✅ T0 T1 T2 · secret never in page for script to read | ✅ T0 T1 T2a | ❌ script still model-authored | ⚠ T0 T1 · script can read pg-held value | ⚠ T0 T2 · T1✗ drv route handler |
| J4 `ru_browser_fetch` | ✅ T0 · same as J3 across a network hop | ✅ T0 T1 T2a · same, on RU VM | ❌ script runs in page | ✅ T0 T1 T2 · secret never in page for script to read | ✅ T0 T1 T2a · login flows never routed here | ❌ script still model-authored | ⚠ T0 T1 · script can read pg-held value | ⚠ T0 T2 · T1✗ drv route handler |
| J5 `capture_cookies` (cookies as result) | ✅ **T0 · block/redact the tool result** | ✅ T0 T1 T2a · handoff goes to a 0600 file, never a tool result | – | – | ✅ **T0 T1 T2a · P5 mandates file handoff — J5's return shape is disallowed** | – | – | – |
| J6 `loadUserTokens` env catch-all | ✅ T0 · redaction doesn't fix env | ✅ T0 T1 · filler reads files directly, never spawns env-injected engines | – | – | ✅ T0 T1 T2a | ❌ env injection independent of typing | – | ❌ env is driver-side |
| J7 OS-level input (prospective) | ⚠ T0(ref) · typing outside drv | ✅ T0 T1 T2a · P2 already better (no focus risk) | – | ❌ pg already holds | ✅ T0 T1 T2a | ⚠ T0 T1(body) T2✗ · focus-miss leak mode | ⚠ T0 T1 · gust | ❌ no-gain |
| J8 MCP `--storage-state` file | ✅ T0 · file not model-visible | ✅ T0 T1 T2a · file 0600 + read-audited = the handoff artifact | – | – | ✅ **T0 T1 T2a · this *is* P5's carrier** | ⚠ T0 T1✗ · any attached drv reads cookies | – | – |

### 4.11 Group K — autofill / heuristics / structure

| ID | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---|---|---|---|---|---|---|---|
| K1 Chrome PM autofill | ✅ T0 · no model involvement | ✅ T0 T1 T2a · seed profile only inside fill-bw | – | ❌ pg already holds | ✅ T0 T1 T2a · profile ships with fill-bw | ⚠ T0 T1✗ · focus decides *where* PM fills (miss ⇒ wrong window) | ✅ **T0 T1 · this row is P7's happy path** · T2✗ pg-sees | ❌ pg already holds |
| K2 `one-time-code` heuristics | ✅ T0 | ✅ T0 T1 T2a · read OTP in filler (audited) | – | ❌ OTP is form-borne | ✅ T0 T1 T2a | ✅ T0 T1 · pg-sees | ⚠ T0 T1 · mostly mobile, gust | – |
| K3 shadow DOM piercing | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | ✅ T0 T1 · focus | ⚠ T0 T1 · gust | ❌ no-gain · pg already holds |
| K4 frames (`frameLocator`) | ⚠ T0(ref) · drv+pg | ✅ T0 T1 · T2 needs L5 | ⚠ T0 · pg holds raw | ❌ pg already holds | ✅ T0 T1 T2a | ✅ T0 T1 · focus | ⚠ T0 T1 · gust | ❌ no-gain · pg already holds |
| K5 contenteditable / rich editors | ⚠ T0(ref) · drv+pg | ⚠ T0 T1 · T2 needs L5 **+ editor may drop `insertText` (visual-empty failure)** | ⚠ T0 · pg holds raw | ❌ pg already holds | ⚠ T0 T1 T2a · verify editor accepted input | ⚠ T0 · T1 body-risk, focus | ❌ PM doesn't fill rich editors | ❌ no-gain · pg already holds |

### 4.12 Sensitive-data sub-classification — where behavior differs

| Data class | Divergences that change the matrix |
|---|---|
| **Password** | Client-side hashing/challenge-response kills P4 form-injection (§2 P4) → header-borne auth or P5 only. A1 fills it (native `Input.insertText`), but **I9 snapshot reads it back** — so the login page must never be snapshotted to the model. Post-submit navigation satisfies L5 for free. |
| **OTP** | Single-use + short TTL ⇒ P5 must run the *whole* flow (password step + OTP step) in the fill browser with a human channel for the code; splitting "agent starts login, filler finishes OTP" re-exposes the shared DOM (T2 vs agent ✗ while both drivers live). `autocomplete="one-time-code"` autofill (K2) is mobile-first — unreliable on desktop Playwright. After successful use the value is dead ⇒ L5 satisfied; screenshot exposure window is before submit. |
| **PII** (name, address, DOB, phone) | Often must remain editable ⇒ cannot clear after fill ⇒ **L5 permanently unsatisfied in the agent's browser** → any row executed agent-side keeps T2 ❌ for its whole lifetime. Address fields are exactly what `Autofill`/K1 cover (G8/P7) — but page JS sees them. P5 keeps agent-side T2 ✓ only while the agent doesn't need to edit the field. |
| **Card number / CVV** | `Autofill` CDP domain is card+address-only (G8); `Autofill.trigger` carries the number through the driver ⇒ T1 ✗ unless triggered browser-side. PCI-like reasoning applies: CVV must never persist (L5 *forced*), never in logs, never in screenshots ⇒ P5 with no-pixel-export, or P4 header-borne tokenization (never send PAN through the agent path at all — prefer: page collects card, agent never touches). Read-back (I9/G3) treats CVV exactly like a password. |
| **Certificates / key files / ID scans** | Only A11/A12/G5 entry paths exist; proxy (P4) and autofill (P7) cannot synthesize multipart bodies. Passphrases *on* the file are read by the filler ⇒ L2 inside the fill-bw; the agent should receive only "upload succeeded". |

---

## 5. Baseline gaps — where trained-assist-agent stands today

Stated as facts with `file:line` (worktree
`/Users/vova/Code/.worktrees/trained-assist-agent/session-interesuet-takoy-vopros-po-20260928-221738`).
These are the leaks any safe-playwright design must not reproduce.

1. **Password as LLM tool args.** `browser_session_login` schema declares
   `password: {type:'string'}` and the handler forwards it to the child env:
   `src/mcp-skills/tools/21-browser-session.js:303-338` (schema `:309-311`, handler
   `:313`, env `:321`). ⇒ T0 broken at emission, T1 broken in child env.
2. **Website credentials as LLM tool args.** `website_credentials_save` takes
   `password` in its schema and stores it plain:
   `src/mcp-skills/tools/98-api-from-website.js:67-89` (schema `:74`, handler `:79`).
   ⇒ T0 broken.
3. **Catch-all env injection.** `loadUserTokens` (`src/user-tokens.js:132`) falls back to
   `extra[LABEL_UPPER] = val` for any service without a special case — raw credential
   JSON into the engine's env: `src/user-tokens.js:225`. ⇒ T1 for the whole engine
   process; env is readable by any same-uid process and lands in core dumps.
4. **Raw cookies as tool result.** `browser_session_capture_cookies` returns the cookie
   string as `output`: `21-browser-session.js:170-222` (return `:210-217`, `:216`).
   ⇒ T0 broken for session tokens.
5. **The good path (ZeroCreds level, keep it).** `browser_session_autologin` reads the
   `0600` file inside the MCP handler (`21-browser-session.js:248-299`, file `:252`) and
   passes `LOGIN_EMAIL`/`LOGIN_PASSWORD` to the child (`:272`); the child
   `infra/browser-session/login.js` reads env (`:8-14`) and attaches
   `connectOverCDP('http://127.0.0.1:9224')` (`:18`). ⇒ T0 ✅ already. Remaining gaps:
   child env is T1-adjacent (same-uid `/proc/*/environ`, core dumps), and the *same*
   persistent browser is the agent's browser — so T2 (agent can `page.evaluate` the
   filled field) is open, and no pixel/snapshot isolation exists.
6. **Model-authored JS can read anything.** `browser_session_evaluate` ships
   `EVAL_SCRIPT` to `page.evaluate` (`21-browser-session.js:127-168`, env `:154`);
   `ru_browser_fetch` ships `script` over HTTP to the RU VM →
   `page.evaluate(script)` (`src/mcp-skills/tools/22-ru-browser.js:12,41-47` →
   `src/ru-edge.js:389`). ⇒ any secret present in the page is one `return el.value`
   away from the model; no wrapper can make arbitrary model JS safe.
7. **`@playwright/mcp@0.0.29` mounted in every engine session**
   (`src/browser.js:126-131`, pin `package.json:27`) ⇒ the I9 snapshot stack is active:
   ARIA snapshots embed `element.value` for password inputs (playwright v1.53.0
   `packages/injected/src/ariaSnapshot.ts:216-218`, no `password` branch;
   `packages/playwright-core/src/server/page.ts:992-1008`), appended to every mutating
   tool result (`mcp/lib/context.js:166`); `browser_type` additionally echoes the typed
   text in its returned code block (`mcp/lib/tools/snapshot.js:145` →
   `mcp/lib/context.js:136`). Also `--storage-state <file>` puts every cookie in one
   driver-readable file (`src/browser.js:131`).
8. **Audit log exists but is weak.** `appendSecretsLog` appends `ISO-ts<TAB>services`
   to `~/agent-tokens/<uid>/.secrets_log` with mode 0600 (`src/user-tokens.js:125-130`),
   called on access (`:227`) and revoke (`:276`). Gaps vs §1.3: local & mutable (no hash
   chain, no off-box copy), logs *service names touched* not *process/reader identity*,
   no alerting, no canaries, no heartbeat.
9. **Driver read paths are structurally open.** Persistent Chrome over CDP
   (`infra/browser-session/login.js:18`), harness-side `page.evaluate` reads
   (`src/site-connector.js:204,244,252`), and Playwright's request-body access
   (`request.postDataBuffer()`) mean any attached driver can recover DOM and network
   secrets at will — the only question is whether audited code ever *does*.
10. **Fill paths in use today.** `locator.fill` for login forms
    (`src/site-connector.js:160,164`) and evaluate+setter tricks for Vue/React sites
    (`src/nalog-login.js:181-189`, `src/getcourse-login.js:68-76`,
    `src/tilda-login.js:80-86`) — all executed by the login scripts (audited path, T0 ✅)
    but with the value resident in child env and the shared browser DOM.

---

## 6. Verdict & recommendation

### 6.1 Defaults for safe-playwright

1. **Default / universal: P5 + P2 — separate audited login browser, server-side fill,
   storage-state handoff.** The whole auth flow (password → OTP via human channel →
   CAPTCHA) runs in a dedicated fill browser whose driver is the minimal audited
   filler; the agent's browser is born with `--storage-state` and never contains the
   credential. Guarantees **T0 + T1 + T2-vs-agent** for every DOM-borne data class, by
   construction, independent of which census row the filler uses internally (A1/A4/B1
   are all acceptable *inside* the filler). This is the only pattern that survives every
   row of §4 without exceptions for page-side frameworks.
2. **Preferred whenever the site allows it: P4 — network-layer injection for
   header-borne auth** (API keys, Bearer/Basic, `Authorization` added by an out-of-process
   proxy). The only combination that reaches **T0+T1+T2 together while the secret is
   live in the agent's own session** — because the secret never enters the page. Rule of
   thumb: *if it can be a header, make it a header.* For form logins with client-side
   hashing, P4 is ❌ — do not promise it.
3. **Mandatory cheap tier: P1 in reference-mode + return-path redaction.** Every tool
   schema that could carry a secret takes `cred://` references only; every result path
   is scrubbed — ARIA snapshot input values (I9), echoed code blocks (I1), screenshots of
   credential pages (I11), console output (I14), cookie dumps (J5). This buys T0 as a
   *floor* and costs one wrapper. It is **not** a substitute for (1): it does nothing for
   T1/T2.
4. **P8 (`page.route` in-driver):** allow only as an implementation detail where process
   separation is genuinely unavailable, documented as `T1 ❌`; prefer re-implementing the
   same rewrite in P4. Remember `Cookie`/`Host`/`Content-Length` overrides are silently
   ignored (playwright.dev/docs/api/class-route#route-continue).
5. **P7 (autofill/PM):** allowed as convenience for card/address (T0 ✅, T1 ✅ only when
   browser-triggered — `Autofill.trigger` from Playwright leaks the card number into the
   driver, G8). Always documented as `T2 ❌`.
6. **P6 (OS-level input):** off by default; per-site allowlist only. Its unique failure
   mode — typing into the wrong focused window — is a *new* leak class that CDP filling
   does not have. It buys little over P2 and loses the actionability feedback loop.

### 6.2 Forbid outright

- Secrets as MCP tool arguments (`browser_session_login` J1;
  `website_credentials_save`, §5 gap 2) — replace with file-lookup/reference.
- Returning raw cookies/tokens as tool results (J5) — handoff is a 0600 file only.
- `loadUserTokens`-style catch-all env injection (J6) — the filler reads files itself.
- Model-authored JS (`browser_session_evaluate`, `ru_browser_fetch`, C8) on any page
  that currently holds or just held a secret — replace with an allowlist of audited RPC
  snippets whose outputs are redaction-checked.
- Screenshots / vision capture of credential pages (I11) in any channel that reaches the
  model; no pixel export at all from the fill browser.
- Snapshotting (`browser_snapshot`, I9) while a credential field holds a value — for the
  pinned stack this means: **the agent must never be pointed at the live login form**.
- `Target.exposeDevToolsProtocol` (G10) and any P3-style bridge that hands the raw value
  to page JS.
- Dual attachment: agent driver + fill process attached to the same browser at the same
  time (serialize; detach before fill).

### 6.3 Machinery required to satisfy "audited code only" (§1.3)

1. Reference-mode arg validation: reject raw-looking secrets; an arg that looks
   like a canary credential → hard error + alert.
2. Canary credentials in the same store + file-access auditing on
   `~/agent-tokens/**` (read-canary) + honey accounts with external login alerts
   (use-canary).
3. Hash-chained, off-box-shipped audit log for every credential access (reader pid/binary,
   service, timestamp, purpose) + dead-man heartbeat alerting.
4. Filler process hardening: no core dumps, no value in argv, env scrubbed, no stdout of
   values, minimal deps, no shell.
5. Build: pinned/reproducible build of the filler + MCP wrapper; the *runtime* controls
   above are what make build integrity sufficient rather than necessary-but-insufficient.

### 6.4 What CDP makes impossible — stated plainly

- **T2 during the fill, against the target page:** impossible (L1). Any page that
  receives a value can read it. The guarantee we can offer is *which* pages ever receive
  a credential: only the ones inside the audited fill browser.
- **T1 for the process that fills:** impossible (L2). We can only choose *which* process
  that is — and then keep it minimal, audited, canaried.
- **T2 read-back for values that stay in the DOM** (PII being edited, card forms, an
  uncleared password box) whenever the agent's driver can see that DOM: impossible while
  attached (I9, G3, F9 all read it). Only full session separation (P5) or field
  clearing/expiry (L5) closes it.
- **T2 against screenshots:** impossible for anything other than `type=password` —
  OTP codes, PII and card numbers are legible in pixels (I11). Hence "no pixel export
  from the fill browser", not "careful screenshotting".
- **T3 against the TLS endpoint:** impossible; the requirement becomes "every endpoint
  is inside the audited boundary" — which makes the mitm proxy (P4) a canaried,
  minimal, separately-audited component, not a loophole.
- **A snapshot-safe `browser_snapshot` on the pinned stack:** not available —
  `element.value` is embedded unconditionally (ariaSnapshot.ts:216-218). Until the
  wrapper redacts it, "never show the model the login page" is the only mitigation.

---

*Research only — no implementation code in this document. Implementation follows the
verdicts in §6; tracking in the linked issues.*
