// Browser session for the golden MCP tool set: one sealed Playwright
// browser per MCP server process, launched with the Playwright default
// pipe (no TCP ports — same invariant as the fill browser, issue #5).

import { chromium } from 'playwright';

import { PolicyError, checkNavigation, collectSnapshot, credentialPageProbe } from './guards.mjs';

export class BrowserSession {
  constructor() {
    this.browser = null;
    this.context = null;
    this.page = null;
    this.refs = new Map(); // ref -> css path (cleared on navigation)
  }

  async start() {
    if (this.browser) return;
    this.browser = await chromium.launch({ headless: true });
    this.context = await this.browser.newContext();
    this.page = await this.context.newPage();
  }

  async close() {
    if (this.browser) {
      await this.browser.close().catch(() => {});
      this.browser = null;
      this.context = null;
      this.page = null;
    }
  }

  requirePage() {
    if (!this.page) throw new PolicyError('browser session is not started');
    return this.page;
  }

  async navigate(url, allowPrivateHosts) {
    await this.start();
    const verdict = checkNavigation(url, allowPrivateHosts);
    if (!verdict.ok) throw new PolicyError(`navigation blocked: ${verdict.reason}`);
    this.refs.clear();
    await this.requirePage().goto(url, { waitUntil: 'domcontentloaded', timeout: 15_000 });
    return { url: this.page.url() };
  }

  // Returns ref-tagged snapshot text, or throws PolicyError when a
  // password field holds a value (fail-closed: the agent does not get
  // to read a page mid-fill).
  async snapshot() {
    await this.start();
    const result = await this.requirePage().evaluate(collectSnapshot);
    if (result.passwordWithValue) {
      throw new PolicyError(
        'snapshot refused: a password field on this page holds a value '
          + '(L5/§6.2 — the agent must never read a live credential form). '
          + 'Navigate away or complete the flow via browser_login.',
      );
    }
    this.refs.clear();
    const lines = [];
    for (const node of result.nodes) {
      this.refs.set(node.ref, node.path);
      const extras = [];
      if (node.value !== undefined && node.value !== '') extras.push(`value=${JSON.stringify(node.value)}`);
      if (node.checked !== undefined) extras.push(node.checked ? 'checked' : 'unchecked');
      if (node.disabled) extras.push('disabled');
      if (node.href) extras.push(`href=${JSON.stringify(node.href)}`);
      const suffix = extras.length > 0 ? ` ${extras.join(' ')}` : '';
      lines.push(`${node.role} ${JSON.stringify(node.name)} [ref=${node.ref}]${suffix}`);
    }
    return lines.join('\n');
  }

  locatorFor(ref) {
    const path = this.refs.get(ref);
    if (!path) {
      throw new PolicyError(`unknown ref "${ref}" — take a fresh browser_snapshot first`);
    }
    return this.requirePage().locator(path).first();
  }

  async click(ref) {
    await this.start();
    try {
      await this.locatorFor(ref).click({ timeout: 5_000 });
    } catch (error) {
      if (error instanceof PolicyError) throw error;
      this.refs.clear();
      throw new PolicyError(`click on ${ref} failed (page changed?) — take a fresh browser_snapshot`);
    }
    return { clicked: ref, url: this.page.url() };
  }

  // Refuses credential inputs outright: secrets never enter the agent's
  // browser (P5). Plain text only.
  async type(ref, text) {
    await this.start();
    const locator = this.locatorFor(ref);
    let info;
    try {
      info = await locator.evaluate((el) => ({
        tag: el.tagName.toLowerCase(),
        type: (el.getAttribute('type') || '').toLowerCase(),
        autocomplete: (el.getAttribute('autocomplete') || '').toLowerCase(),
      }));
    } catch {
      this.refs.clear();
      throw new PolicyError(`ref ${ref} is stale — take a fresh browser_snapshot`);
    }
    const isCredentialInput = info.tag === 'input' && info.type === 'password';
    const isOtpInput = info.autocomplete.includes('one-time-code');
    if (isCredentialInput || isOtpInput) {
      throw new PolicyError(
        'refuses to type into a credential input (password/OTP): secrets never enter '
          + "the agent's browser — use browser_login (storage-state handoff, P5)",
      );
    }
    await locator.fill(String(text), { timeout: 5_000 });
    return { typed: ref, length: String(text).length };
  }

  async wait({ timeMs, ref, state }) {
    await this.start();
    if (ref) {
      const locator = this.locatorFor(ref);
      if (state === 'hidden') await locator.waitFor({ state: 'hidden', timeout: 5_000 });
      else await locator.waitFor({ state: 'visible', timeout: 5_000 });
      return { waited: 'ref', ref, state: state ?? 'visible' };
    }
    const ms = Math.min(Math.max(Number(timeMs) || 500, 0), 10_000);
    await this.requirePage().waitForTimeout(ms);
    return { waited: 'time', timeMs: ms };
  }

  async screenshot({ fullPage }) {
    await this.start();
    const page = this.requirePage();
    const state = await page.evaluate(credentialPageProbe);
    if (state.hasPassword || state.otpWithValue || state.cardWithValue) {
      throw new PolicyError(
        'screenshot refused: this page presents a credential field (pixel policy U7 — '
          + 'OTP/PII are legible in pixels)',
      );
    }
    const buffer = await page.screenshot({ fullPage: Boolean(fullPage), type: 'png' });
    return { mime: 'image/png', data: buffer.toString('base64') };
  }
}
