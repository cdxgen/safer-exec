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
import { tmpdir } from 'node:os';
import { getSslPaths } from './sslhelper.js';
import { getPnpmPaths } from './pnpm.js';

function getNodeDir() {
  return dirname(process.execPath);
}

function getNodeLibDir() {
  const nodeDir = getNodeDir();
  return nodeDir.replace(/bin$/, 'lib');
}

/**
 * Return the Poku policy configuration.
 *
 * @returns {Object} The policy configuration
 */
export function pokuPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const temp = tmpdir();

  return {
    // 1. NETWORK RESTRICTIONS
    allowHosts: [],           // No external network
    allowLoopback: true,      // Allow loopback for mock HTTP servers (Bug #5)

    // 2. READ PATHS
    readPaths: [
      getNodeDir(),
      getNodeLibDir(),
      ...getSslPaths(),
      cwd,
      join(home, 'go', 'pkg', 'mod'),  // Go module cache (Obs #3)
      join(home, '.m2'),               // Maven local repo
      join(home, '.gradle'),           // Gradle home
      join(home, '.cargo'),            // Cargo cache
      ...getPnpmPaths(),
    ],

    // 3. WRITE PATHS
    writePaths: [
      cwd,
      temp,
      join(home, '.npm'),              // npm cache (Obs #5)
      join(home, '.gradle'),           // Gradle build cache
    ],

    // 4. ENVIRONMENT CONTROLS
    env: {
      CI: process.env.CI || '',
      PNPM_HOME: process.env.PNPM_HOME || '',
    },

    // 5. EXECUTION CONTROLS
    blockFork: false,          // Test runners must spawn subprocesses
    blockExec: [],             // Allow test runners to execute node/etc.
  };
}

export default pokuPolicy;
