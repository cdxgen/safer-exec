/**
 * Bun ecosystem policy.
 *
 * Hardened profile for running the Bun runtime and package manager. Covers:
 * - Bun registry hosts
 * - Bun binary detection
 * - SSL certificate paths
 * - Bun cache directory isolation
 *
 * @module policies/bun
 */

import { join } from 'node:path';
import { getSslPaths } from './sslhelper.js';
import { execSync } from 'node:child_process';

function resolveBunPaths(home) {
  let bunBin = '/usr/local/bin/bun';
  let bunInstall = join(home, '.bun');

  try {
    const bin = execSync('which bun', { encoding: 'utf-8' }).trim();
    if (bin) {
      bunBin = bin;
    }
  } catch {}

  if (process.env.BUN_INSTALL) {
    bunInstall = process.env.BUN_INSTALL;
  }

  return { bunBin, bunInstall };
}

export function bunPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const { bunBin, bunInstall } = resolveBunPaths(home);

  return {
    allowHosts: [
      'registry.npmjs.org',
      'jsr.io',
    ],

    readPaths: [
      bunBin,
      bunInstall,
      ...getSslPaths(),
      join(cwd, 'package.json'),
      join(cwd, 'bun.lockb'),
      join(cwd, 'bunfig.toml'),
    ],

    writePaths: [
      join(cwd, 'node_modules'),
      join(cwd, 'bun.lockb'),
      bunInstall,
    ],

    env: {
      BUN_INSTALL: bunInstall,
      DO_NOT_TRACK: '1',
    },

    blockFork: true,

    denyPersistenceWrites: true,

    blockInterpreters: true,
    blockExec: ['*'],
  };
}

export default bunPolicy;