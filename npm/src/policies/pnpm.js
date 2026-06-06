/**
 * PNPM ecosystem policy.
 *
 * Hardened profile for running the PNPM package manager. Based on the
 * npm policy with PNPM-specific overrides for registry and cache paths.
 *
 * @module policies/pnpm
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
 * Return the PNPM ecosystem policy object.
 *
 * @returns {Object} The policy configuration
 */
export function pnpmPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const temp = tmpdir();

  return {
    // 1. NETWORK RESTRICTIONS
    allowHosts: [
      'registry.npmjs.org',
    ],

    // 2. READ PATHS
    readPaths: [
      getNodeDir(),
      getNodeLibDir(),
      ...getSslPaths(),
      join(cwd, 'package.json'),
      join(cwd, 'package-lock.json'),
      join(cwd, 'pnpm-lock.yaml'),
      join(cwd, 'pnpm-workspace.yaml'), // Added: Essential for PNPM monorepos
      join(cwd, '.npmrc'),
      join(cwd, '.pnpmfile.cjs'),
      join(home, '.npmrc'),             // Added: PNPM often requires global auth tokens
      join(home, '.config', 'pnpm'),    // Added: Global PNPM config path
      temp,                             // Added: Temp dir is required for staging tarballs
    ],

    // 3. WRITE PATHS
    writePaths: [
      join(cwd, 'node_modules'),
      join(cwd, 'pnpm-lock.yaml'),
      join(home, '.pnpm-store'),

      // Cross-platform PNPM global state directories
      join(home, '.local', 'share', 'pnpm'),                                   // Linux
      ...(process.platform === 'darwin' ? [join(home, 'Library', 'pnpm')] : []), // macOS
      ...(process.env.LOCALAPPDATA ? [join(process.env.LOCALAPPDATA, 'pnpm')] : []), // Windows

      temp, // Added: PNPM must write to OS temp to extract downloaded packages safely
    ],

    // 4. ENVIRONMENT CONTROLS
    env: {
      npm_config_loglevel: 'warn',
      // Added defense-in-depth: Tells PNPM natively not to attempt running lifecycle scripts
      npm_config_ignore_scripts: 'true',
    },

    // 5. EXECUTION CONTROLS
    blockFork: true,
    blockExec: ['*'],
  };
}

export default pnpmPolicy;