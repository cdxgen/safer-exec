/**
 * CDXGEN SCA scanner policy.
 *
 * Hardened policy specifically designed for running cdxgen (Software Bill
 * of Materials generator) under the sandbox. Allows necessary package manager
 * executions, caches, and loopback connectivity.
 *
 * @module policies/cdxgen
 */

import { dirname, join } from 'node:path';
import { realpathSync } from 'node:fs';
import { getSslPaths } from './sslhelper.js';
import { getPnpmPaths } from './pnpm.js';

function getNodeDir() {
  try {
    return dirname(realpathSync(process.execPath));
  } catch {
    return dirname(process.execPath);
  }
}

function getNodeLibDir() {
  const nodeDir = getNodeDir();
  const libDir = nodeDir.replace(/bin$/, 'lib');
  return join(libDir, 'node_modules');
}

/**
 * Return the CDXGEN policy configuration.
 *
 * @returns {Object} The policy configuration
 */
export function cdxgenPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();

  return {
    // 1. NETWORK RESTRICTIONS
    allowHosts: [
      'registry.npmjs.org',
      'registry.yarnpkg.com',
      'pypi.org',
      'files.pythonhosted.org',
      'repo.maven.apache.org',
      'crates.io',
      'proxy.golang.org',
      'goproxy.io',
    ],
    allowLoopback: true,

    // 2. READ PATHS
    readPaths: [
      getNodeDir(),
      getNodeLibDir(),
      ...getSslPaths(),
      cwd,
      join(home, 'go', 'pkg', 'mod'),
      join(home, '.m2'),
      join(home, '.gradle'),
      join(home, '.cargo'),
      join(home, '.npm'),
      join(home, '.config', 'pnpm'),
      ...getPnpmPaths(),
    ],

    // 3. WRITE PATHS
    writePaths: [
      cwd,
      join(home, '.npm'),
      join(home, '.gradle'),
      join(home, '.cargo'),
      join(home, '.cache', 'pip'),
      join(home, '.cache', 'ms-playwright'),
    ],

    // 4. ENVIRONMENT CONTROLS
    env: {
      PATH: process.env.PATH || '',
    },

    // 5. EXECUTION CONTROLS
    blockFork: false,
    blockExec: [],
  };
}

export default cdxgenPolicy;
