/**
 * Poku test runner policy.
 *
 * Hardened policy specifically designed for running Poku or other Node.js
 * test runners under the sandbox. Allows fork/exec and loopback interfaces
 * for local test servers.
 *
 * @module policies/poku
 */

import { dirname, join } from 'node:path';
import { getSslPaths } from './sslhelper.js';
import { getPnpmPaths } from './pnpm.js';

function getNodeDir() {
  return dirname(process.execPath);
}

function getNodeLibDir() {
  const nodeDir = getNodeDir();
  const libDir = nodeDir.replace(/bin$/, 'lib');
  return join(libDir, 'node_modules');
}

/**
 * Return the Poku policy configuration.
 *
 * @returns {Object} The policy configuration
 */
export function pokuPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const temp = join(home, '.npm', '_cacache', 'tmp');

  return {
    // 1. NETWORK RESTRICTIONS
    allowHosts: [],
    allowLoopback: true,

    // 2. READ PATHS
    readPaths: [
      getNodeDir(),
      getNodeLibDir(),
      ...getSslPaths(),
      join(cwd, 'package.json'),
      join(cwd, 'pnpm-lock.yaml'),
      join(home, '.npmrc'),
      join(home, 'go', 'pkg', 'mod'),
      join(home, '.m2'),
      join(home, '.gradle'),
      join(home, '.cargo'),
      ...(process.platform === 'darwin' ? [join(home, 'Library', 'Preferences', 'pnpm')] : []),
      ...getPnpmPaths(),
    ],

    // 3. WRITE PATHS
    writePaths: [
      join(cwd, 'node_modules'),
      temp,
      join(home, '.npm'),
      join(home, '.gradle'),
    ],

    // 4. ENVIRONMENT CONTROLS
    env: {
      CI: process.env.CI || '',
      PNPM_HOME: process.env.PNPM_HOME || '',
    },

    // 5. EXECUTION CONTROLS
    blockFork: false,
    denyPersistenceWrites: true,
    blockInterpreters: true,
    blockExec: [],
  };
}

export default pokuPolicy;
