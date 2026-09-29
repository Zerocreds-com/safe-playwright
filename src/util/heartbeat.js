'use strict';

const fs = require('node:fs');
const path = require('node:path');

/** Read a heartbeat file; returns `{ ts, raw }` (ms epoch) or null. */
function readHeartbeat(filePath) {
  try {
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const ts = Date.parse(raw && raw.ts);
    if (!Number.isFinite(ts)) return null;
    return { ts, raw };
  } catch {
    return null;
  }
}

/** Write a heartbeat file atomically (tmp file + rename). */
function writeHeartbeat(filePath, { now, pid } = {}) {
  const value = now ? now() : Date.now();
  const iso = typeof value === 'string' ? value : new Date(value).toISOString();
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ ts: iso, pid: pid || process.pid }) + '\n');
  fs.renameSync(tmp, filePath);
  return iso;
}

module.exports = { readHeartbeat, writeHeartbeat };
