// Separate-OS-user support for the fill browser (P4 scope item 1b).
//
// The fill worker is spawned as a dedicated "slot" OS user so the agent
// process cannot read the filler's memory, environment or core dumps
// (same-uid exposure, epic #2 threat U6 / control C15).
//
// Switching uid requires either an existing dedicated account plus
// passwordless sudo, or the ability to create one (root). This module
// reports whether the switch is feasible and, when it is not, returns a
// human-readable blocker so the PoC can document it instead of silently
// degrading to same-uid execution.

import { execFileSync } from 'node:child_process';

export const SLOT_USER_ENV = 'SAFE_PLAYWRIGHT_SLOT_USER';

function runsSuccessfully(command, args) {
  try {
    execFileSync(command, args, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

export function configuredSlotUser() {
  const user = process.env[SLOT_USER_ENV];
  return user && user.trim() ? user.trim() : null;
}

export function userExists(user) {
  return runsSuccessfully('id', ['-u', user]);
}

export function passwordlessSudoAvailable() {
  return runsSuccessfully('sudo', ['-n', 'true']);
}

export function canSwitchUser() {
  const user = configuredSlotUser();
  if (!user) {
    return {
      feasible: false,
      user: null,
      blocker:
        `No slot user configured (set ${SLOT_USER_ENV}). Without a designated ` +
        'dedicated OS user there is no account to switch to, and creating one ' +
        'requires root privileges.',
    };
  }
  if (!userExists(user)) {
    return {
      feasible: false,
      user,
      blocker:
        `Slot user "${user}" does not exist (id -u failed). Creating a new OS ` +
        'user requires root privileges, which this environment does not grant ' +
        'non-interactively.',
    };
  }
  if (!passwordlessSudoAvailable()) {
    return {
      feasible: false,
      user,
      blocker:
        `Slot user "${user}" exists but passwordless sudo is unavailable ` +
        '("sudo -n true" fails: a password is required). Switching uid needs ' +
        'either passwordless sudo for the launcher or an equivalent root ' +
        'mechanism (setuid helper, container entrypoint, service running as ' +
        'the slot user).',
    };
  }
  return { feasible: true, user, blocker: null };
}

// Build the spawn command for the fill worker: plain `node` when the switch
// is infeasible, `sudo -n -u <slot-user> -- env ... node` when it is.
export function fillWorkerSpawnCommand({ nodeBinary, workerScript, workerArgs, switchInfo, extraEnv = {} }) {
  const command = [nodeBinary, workerScript, ...workerArgs];
  if (!switchInfo.feasible) return { command: command[0], args: command.slice(1) };

  const envAssignments = Object.entries(extraEnv).flatMap(([key, value]) => [`${key}=${value}`]);
  return {
    command: 'sudo',
    args: ['-n', '-u', switchInfo.user, '--', 'env', ...envAssignments, ...command],
  };
}
