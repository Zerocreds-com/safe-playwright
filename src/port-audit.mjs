// Process-tree and TCP-port auditing for the P4 fill browser.
//
// The fill browser must run over Playwright's default transport
// (--remote-debugging-pipe, two inherited fds) and must never open a
// listening TCP port: a listening CDP port is a shared resource any
// local process can attach to (threat A3 in epic #2).
//
// Auditing is done from outside the fill worker: the parent test walks
// the worker's process tree and inspects every descendant with `ps`,
// `lsof` (macOS) or /proc (Linux).

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';

function run(command, args) {
  try {
    return {
      ok: true,
      stdout: execFileSync(command, args, {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      }),
    };
  } catch (error) {
    return {
      ok: false,
      stdout: error.stdout ? String(error.stdout) : '',
      error,
    };
  }
}

export function processTable() {
  const { stdout } = run('ps', ['-axo', 'pid=,ppid=']);
  const table = new Map();
  for (const line of stdout.split('\n')) {
    const match = line.trim().match(/^(\d+)\s+(\d+)$/);
    if (match) table.set(Number(match[1]), Number(match[2]));
  }
  return table;
}

export function descendantsOf(rootPid) {
  const table = processTable();
  const found = new Set([rootPid]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const [pid, ppid] of table) {
      if (found.has(ppid) && !found.has(pid)) {
        found.add(pid);
        changed = true;
      }
    }
  }
  return [...found].sort((a, b) => a - b);
}

export function commandLine(pid) {
  const { stdout } = run('ps', ['-o', 'command=', '-p', String(pid)]);
  return stdout.trim();
}

function listeningPortsDarwin(pids) {
  const wanted = new Set(pids.map(String));
  const result = run('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN', '-F', 'pn']);
  // lsof exits non-zero when nothing matches; stdout then holds no file
  // entries, which correctly reads as "no listening sockets".
  const ports = [];
  let currentPid = null;
  for (const line of result.stdout.split('\n')) {
    if (!line) continue;
    if (line.startsWith('p')) {
      currentPid = line.slice(1);
    } else if (line.startsWith('n') && currentPid && wanted.has(currentPid)) {
      const address = line.slice(1);
      const port = Number(address.slice(address.lastIndexOf(':') + 1));
      if (Number.isInteger(port)) ports.push({ pid: Number(currentPid), address, port });
    }
  }
  return ports;
}

function listeningPortsLinux(pids) {
  const inodes = new Map();
  for (const pid of pids) {
    let fds = [];
    try {
      fds = fs.readdirSync(`/proc/${pid}/fd`);
    } catch {
      continue; // process exited between `ps` and this read
    }
    for (const fd of fds) {
      try {
        const link = fs.readlinkSync(`/proc/${pid}/fd/${fd}`);
        const match = link.match(/^socket:\[(\d+)\]$/);
        if (match) inodes.set(match[1], pid);
      } catch {
        // fd vanished or is not a socket — ignore
      }
    }
  }
  const ports = [];
  for (const file of ['/proc/net/tcp', '/proc/net/tcp6']) {
    let content = '';
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    for (const line of content.split('\n').slice(1)) {
      const fields = line.trim().split(/\s+/);
      if (fields.length < 10) continue;
      if (fields[3] !== '0A') continue; // TCP_LISTEN
      const inode = fields[9];
      if (!inodes.has(inode)) continue;
      const port = parseInt(fields[1].split(':')[1], 16);
      ports.push({ pid: inodes.get(inode) ?? null, address: fields[1], port });
    }
  }
  return ports;
}

export function listeningTcpPorts(pids) {
  return process.platform === 'darwin' ? listeningPortsDarwin(pids) : listeningPortsLinux(pids);
}

const BROWSER_PATTERN = /chrome|chromium|headless[-_]shell/i;

// Audit one process tree: are its browser processes pipe-transport only,
// with zero listening TCP ports?
export function auditProcessTree(rootPid) {
  const pids = descendantsOf(rootPid);
  const processes = pids.map((pid) => ({ pid, command: commandLine(pid) }));
  const browserProcesses = processes.filter((entry) => BROWSER_PATTERN.test(entry.command));
  const pipeTransport = browserProcesses.some((entry) =>
    entry.command.includes('--remote-debugging-pipe'),
  );
  const remoteDebuggingPortFlag = browserProcesses.filter((entry) =>
    /--remote-debugging-port(?:[=\s]|$)/.test(entry.command),
  );
  const listening = listeningTcpPorts(pids);
  const mainBrowser = browserProcesses.find((entry) => !/--type=/.test(entry.command));
  return {
    rootPid,
    pids,
    browserPids: browserProcesses.map((entry) => entry.pid),
    pipeTransport,
    remoteDebuggingPortFlagPids: remoteDebuggingPortFlag.map((entry) => entry.pid),
    listeningTcpPorts: listening,
    mainBrowserCommandLine: mainBrowser ? mainBrowser.command : null,
  };
}
