'use strict';

const { readHeartbeat } = require('../util/heartbeat');

/**
 * Dead-man heartbeat watch (stub).
 *
 * A subject (`daemon`, `verifier`, …) writes a heartbeat file; this watch
 * raises an alert when the subject goes silent for longer than `ttlMs`.
 * Silence is the signal: an attacker who kills the subject is caught by the
 * absence of heartbeats, because the alert is emitted here — outside the
 * subject — and not by the subject itself.
 *
 * One alert per outage; re-armed by the next fresh heartbeat.
 */
class DeadManWatch {
  constructor({ heartbeatPath, ttlMs, alertChannel, subject, now, graceMs = 0 }) {
    if (!heartbeatPath) throw new Error('DeadManWatch requires heartbeatPath');
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new Error('DeadManWatch requires a positive ttlMs');
    }
    if (!alertChannel) throw new Error('DeadManWatch requires an alertChannel');
    this.heartbeatPath = heartbeatPath;
    this.ttlMs = ttlMs;
    this.alertChannel = alertChannel;
    this.subject = subject || 'subject';
    this.now = now || Date.now;
    this.graceMs = graceMs;
    this.startedAt = this.now();
    this.alerted = false;
    this.timer = null;
  }

  check() {
    const nowMs = this.now();
    if (nowMs < this.startedAt + this.graceMs) {
      return { silent: false, alerted: false, reason: 'grace' };
    }
    const beat = readHeartbeat(this.heartbeatPath);
    const silent = !beat || nowMs - beat.ts > this.ttlMs;
    if (!silent) {
      this.alerted = false;
      return { silent: false, alerted: false };
    }
    if (this.alerted) {
      return { silent: true, alerted: false, reason: 'already-alerted' };
    }
    this.alerted = true;
    this.alertChannel.emit('deadman.silent', {
      subject: this.subject,
      heartbeatPath: this.heartbeatPath,
      ttlMs: this.ttlMs,
      lastBeatAt: beat ? new Date(beat.ts).toISOString() : null,
    });
    return { silent: true, alerted: true };
  }

  start(intervalMs) {
    const period = intervalMs || Math.max(250, Math.floor(this.ttlMs / 4));
    this.stop();
    this.timer = setInterval(() => this.check(), period);
    if (typeof this.timer.unref === 'function') this.timer.unref();
    return this;
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    return this;
  }
}

module.exports = { DeadManWatch };
