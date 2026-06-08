/**
 * PNPM Install policy.
 *
 * Hardened policy specifically designed for running pnpm install commands.
 * Allows fork/exec execution for sub-commands/lifecycle scripts and grants
 * write access to the working directory and user pnpm home store.
 *
 * @module policies/pnpmInstall
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
 * Return the PNPM install policy configuration.
 *
 * @returns {Object} The policy configuration
 */
export function pnpmInstallPolicy() {
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
      cwd,
      join(home, '.npmrc'),
      join(home, '.config', 'pnpm'),
      ...(process.platform === 'darwin' ? [join(home, 'Library', 'Preferences', 'pnpm')] : []),
      '/usr',
      '/opt',
      '/etc',
      temp,
    ],

    // 3. WRITE PATHS
    writePaths: [
      cwd,
      join(home, '.pnpm-store'),
      join(home, '.local', 'share', 'pnpm'),
      ...(process.platform === 'darwin' ? [join(home, 'Library', 'pnpm')] : []),
      ...(process.env.LOCALAPPDATA ? [join(process.env.LOCALAPPDATA, 'pnpm')] : []),
      temp,
    ],

    // 4. ENVIRONMENT CONTROLS
    env: {
      npm_config_loglevel: 'warn',
      npm_config_ignore_scripts: 'true',
    },

    // 5. EXECUTION CONTROLS
    blockFork: false,
    blockExec: [],
  };
}

export default pnpmInstallPolicy;
