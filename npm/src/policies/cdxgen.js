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
import { tmpdir } from 'node:os';
import { getSslPaths } from './sslhelper.js';

function getNodeDir() {
  return dirname(process.execPath);
}

function getNodeLibDir() {
  const nodeDir = getNodeDir();
  return nodeDir.replace(/bin$/, 'lib');
}

/**
 * Return the CDXGEN policy configuration.
 *
 * @returns {Object} The policy configuration
 */
export function cdxgenPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const temp = tmpdir();

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
      'goproxy.cn',
    ],
    allowLoopback: true,      // Allow local localhost binding/connecting

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
      '/Users/prabhu/work/cdxgen/cdxgen',
      '/Users/prabhu/work/cdxgen/safer-exec',
    ],

    // 3. WRITE PATHS
    writePaths: [
      cwd,
      temp,
      join(home, '.npm'),
      join(home, '.gradle'),
      join(home, '.cargo'),
      join(home, '.cache'),
    ],

    // 4. ENVIRONMENT CONTROLS
    env: {
      NODE_ENV: process.env.NODE_ENV || 'production',
      PATH: process.env.PATH || '',
    },

    // 5. EXECUTION CONTROLS
    blockFork: false,          // SCA needs to spawn package managers
    blockExec: [],             // Allow execution of child processes (mvn, gradle, npm, pip, go, cargo, etc.)
  };
}

export default cdxgenPolicy;
