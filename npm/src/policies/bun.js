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
import { getSslPaths, isMac } from './sslhelper.js';

function resolveBunPaths() {
  if (isMac) {
    return {
      bunBin: '/usr/local/bin/bun',
      bunLib: '/usr/local/lib',
    };
  }
  return {
    bunBin: '/usr/bin/bun',
    bunLib: '/usr/lib',
  };
}

export function bunPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const { bunBin, bunLib } = resolveBunPaths();

  return {
    allowHosts: [
      'registry.npmjs.org',
      'jsr.io',
      'cdn.jsdelivr.net',
    ],

    readPaths: [
      bunBin,
      bunLib,
      ...getSslPaths(),
      join(cwd, 'package.json'),
      join(cwd, 'bun.lockb'),
      join(cwd, 'bunfig.toml'),
    ],

    writePaths: [
      join(cwd, 'node_modules'),
      join(cwd, 'bun.lockb'),
      join(home, '.bun'),
    ],

    env: {
      BUN_INSTALL: join(home, '.bun'),
      // Disable telemetry and tracking
      DO_NOT_TRACK: '1',
    },

    /** OS-level blocking to violently catch and deny postinstall script executions */
    blockFork: true,
    blockExec: ['*'],
  };
}

export default bunPolicy;