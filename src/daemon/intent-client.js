'use strict';

/**
 * Daemon-side client for the external verifier.
 *
 * This is the entire state-mutation surface the daemon has: two HTTP calls.
 * It carries no alert capability (no import of `alert-channel`), so a
 * subverted daemon cannot suppress or forge verifier alerts (epic #2, A5).
 */

class IntentClient {
  constructor({ baseUrl, timeoutMs = 10_000 } = {}) {
    if (!baseUrl) throw new Error('IntentClient requires baseUrl');
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.timeoutMs = timeoutMs;
  }

  async request(pathname, body) {
    const response = await fetch(`${this.baseUrl}${pathname}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const payload = await response.json().catch(() => ({}));
    return { status: response.status, payload };
  }

  /** Phase 1: submit the mutation, receive the verifier-issued intent. */
  async submitIntent(mutation) {
    const { status, payload } = await this.request('/intent', { mutation });
    if (status !== 200 || !payload.intent) {
      throw new Error(payload.error || `intent request failed (HTTP ${status})`);
    }
    return payload.intent;
  }

  /** Phase 2: present the intent together with the exact mutation. */
  async applyIntent(intentId, mutation) {
    const { payload } = await this.request('/apply', { intentId, mutation });
    return payload;
  }

  /** Convenience: the two phases back to back. */
  async mutate(mutation) {
    const intent = await this.submitIntent(mutation);
    return this.applyIntent(intent.id, mutation);
  }
}

module.exports = { IntentClient };
