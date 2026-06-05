/**
 * PNPM ecosystem policy.
 *
 * Hardened profile for running the PNPM package manager. Based on the
 * npm policy with PNPM-specific overrides for registry and cache paths.
 *
 * @module policies/pnpm
 */

import { dirname, join } from 'node:path';
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

  return {
    allowHosts: [
      'registry.npmjs.org',
      'registry.yarnpkg.com',
      'cdn.jsdelivr.net',
    ],

    readPaths: [
      getNodeDir(),
      getNodeLibDir(),
      ...getSslPaths(),
      join(cwd, 'package.json'),
      join(cwd, 'package-lock.json'),
      join(cwd, 'pnpm-lock.yaml'),
      join(cwd, '.npmrc'),
      join(cwd, '.pnpmfile.cjs'),
    ],

    writePaths: [
      join(cwd, 'node_modules'),
      join(cwd, 'pnpm-lock.yaml'),
      join(home, '.npm'),
      join(home, '.pnpm-store'),
      join(home, '.local', 'share', 'pnpm'),
    ],

    env: {
      npm_config_loglevel: 'warn',
    },

    blockFork: true,
    blockExec: ['*'],
  };
}

export default pnpmPolicy;
