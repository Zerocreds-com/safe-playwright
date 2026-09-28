'use strict';

const { writeHeartbeat } = require('../util/heartbeat');

/**
 * Daemon-side heartbeat writer (stub).
 *
 * The daemon only says "I am alive" into a file. It has no alerting code
 * (no import of the alert channel): whoever watches this file — the verifier
 * for daemon silence, a supervisor for verifier silence — is the one that
 * pages. Killing the daemon therefore stops the heartbeat but cannot stop
 * the alert.
 */
class HeartbeatWriter {
  constructor({ filePath, now, pid } = {}) {
    if (!filePath) throw new Error('HeartbeatWriter requires filePath');
    this.filePath = filePath;
    this.now = now || Date.now;
    this.pid = pid || process.pid;
    this.timer = null;
  }

  beat() {
    return writeHeartbeat(this.filePath, { now: this.now, pid: this.pid });
  }

  start(intervalMs) {
    this.stop();
    this.beat();
    this.timer = setInterval(() => this.beat(), intervalMs);
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

module.exports = { HeartbeatWriter };
