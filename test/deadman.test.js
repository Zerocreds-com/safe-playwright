'use strict';

const { test, describe, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { cleanupTempDirs, tempDir } = require('./helpers');
const { AlertChannel } = require('../src/attestation/alert-channel');
const { DeadManWatch } = require('../src/attestation/deadman');
const { writeHeartbeat, readHeartbeat } = require('../src/util/heartbeat');
const { HeartbeatWriter } = require('../src/daemon/heartbeat');

const DAEMON_DIR = path.join(__dirname, '..', 'src', 'daemon');

after(cleanupTempDirs);

function clockFixture(startMs = 1_700_000_000_000) {
  const clock = { value: startMs };
  return { clock, now: () => clock.value };
}

describe('dead-man heartbeat', () => {
  test('verifier silence pages an alert, and the daemon generates it nowhere (issue #3 AC3)', () => {
    const dir = tempDir();
    const heartbeatPath = path.join(dir, 'verifier.hb');
    const alertPath = path.join(dir, 'supervisor-alerts.jsonl');
    const { clock, now } = clockFixture();

    const captured = [];
    const supervisorChannel = new AlertChannel({ filePath: alertPath, emitter: 'supervisor' });
    supervisorChannel.onAlert((alert) => captured.push(alert));

    writeHeartbeat(heartbeatPath, { now });
    const watch = new DeadManWatch({
      heartbeatPath,
      ttlMs: 10_000,
      alertChannel: supervisorChannel,
      subject: 'verifier',
      now,
    });

    clock.value += 5_000;
    assert.equal(watch.check().silent, false);

    clock.value += 6_000; // past the TTL: the verifier went silent
    const result = watch.check();

    assert.equal(result.silent, true);
    assert.equal(result.alerted, true);
    assert.equal(captured.length, 1);
    assert.equal(captured[0].kind, 'deadman.silent');
    assert.equal(captured[0].emitter, 'supervisor');
    assert.equal(captured[0].detail.subject, 'verifier');

    // Persisted out-of-band, not inside any daemon process.
    const onDisk = fs
      .readFileSync(alertPath, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    assert.equal(onDisk.length, 1);
    assert.notEqual(onDisk[0].emitter, 'daemon');
  });

  test('daemon silence is alerted by the verifier-owned channel', () => {
    const dir = tempDir();
    const heartbeatPath = path.join(dir, 'daemon.hb');
    const { clock, now } = clockFixture();

    const captured = [];
    const verifierChannel = new AlertChannel({ emitter: 'verifier' });
    verifierChannel.onAlert((alert) => captured.push(alert));

    writeHeartbeat(heartbeatPath, { now });
    const watch = new DeadManWatch({
      heartbeatPath,
      ttlMs: 5_000,
      alertChannel: verifierChannel,
      subject: 'daemon',
      now,
    });

    assert.equal(watch.check().silent, false);
    clock.value += 5_001;
    assert.equal(watch.check().alerted, true);
    assert.equal(captured[0].emitter, 'verifier');
    assert.equal(captured[0].detail.subject, 'daemon');
  });

  test('one alert per outage, re-armed by the next heartbeat', () => {
    const dir = tempDir();
    const heartbeatPath = path.join(dir, 'subject.hb');
    const { clock, now } = clockFixture();

    const captured = [];
    const channel = new AlertChannel({ emitter: 'verifier' });
    channel.onAlert((alert) => captured.push(alert));

    writeHeartbeat(heartbeatPath, { now });
    const watch = new DeadManWatch({ heartbeatPath, ttlMs: 1_000, alertChannel: channel, subject: 'daemon', now });

    clock.value += 2_000;
    assert.equal(watch.check().alerted, true);
    assert.equal(watch.check().alerted, false, 'must not page repeatedly for one outage');
    assert.equal(captured.length, 1);

    writeHeartbeat(heartbeatPath, { now });
    assert.equal(watch.check().silent, false);

    clock.value += 2_000;
    assert.equal(watch.check().alerted, true, 'a new outage must page again');
    assert.equal(captured.length, 2);
  });

  test('a missing heartbeat file pages after the grace period', () => {
    const dir = tempDir();
    const heartbeatPath = path.join(dir, 'never-written.hb');
    const { clock, now } = clockFixture();

    const captured = [];
    const channel = new AlertChannel({ emitter: 'verifier' });
    channel.onAlert((alert) => captured.push(alert));

    const watch = new DeadManWatch({
      heartbeatPath,
      ttlMs: 1_000,
      alertChannel: channel,
      subject: 'verifier',
      now,
      graceMs: 500,
    });

    assert.equal(watch.check().reason, 'grace');
    clock.value += 600;
    assert.equal(watch.check().alerted, true);
    assert.equal(captured[0].detail.lastBeatAt, null);
  });

  test('the daemon heartbeat writer produces a file the watch can read', () => {
    const dir = tempDir();
    const heartbeatPath = path.join(dir, 'daemon.hb');
    const writer = new HeartbeatWriter({ filePath: heartbeatPath });
    writer.beat();

    const beat = readHeartbeat(heartbeatPath);
    assert.ok(beat);
    assert.ok(Number.isFinite(beat.ts));
    assert.equal(typeof beat.raw.pid, 'number');
  });
});

describe('alert ownership is structural, not conventional', () => {
  test('no daemon source imports the alert channel or emits alerts', () => {
    const files = fs.readdirSync(DAEMON_DIR).filter((name) => name.endsWith('.js'));
    assert.ok(files.length >= 2, 'expected daemon-side modules');

    for (const name of files) {
      const source = fs.readFileSync(path.join(DAEMON_DIR, name), 'utf8');
      assert.doesNotMatch(source, /require\(.*alert-channel/, `${name} must not import the alert channel`);
      assert.doesNotMatch(source, /\.emit\(/, `${name} must not emit alerts`);
    }

    for (const name of files) {
      const exports = require(path.join(DAEMON_DIR, name));
      const exportNames = Object.keys(exports);
      assert.equal(
        exportNames.filter((key) => /alert/i.test(key)).length,
        0,
        `${name} must export no alert capability`
      );
    }
  });

  test('alerts are stamped with the verifier identity by default', () => {
    const channel = new AlertChannel({});
    assert.equal(channel.emitter, 'verifier');
    const alert = channel.emit('test.kind', { ping: true });
    assert.equal(alert.emitter, 'verifier');
    assert.equal(channel.listeners.length, 0);
  });
});
