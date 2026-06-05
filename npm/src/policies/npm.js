/**
 * NPM / Yarn / PNPM ecosystem policy.
 *
 * Hardened profile for running JavaScript package managers. Covers:
 * - NPM registry hosts
 * - Yarn registry hosts
 * - PNPM registry hosts
 * - Node binary detection
 * - SSL certificate paths
 * - Cache directory isolation
 *
 * @module policies/npm
 */

import { dirname, join } from 'node:path';
import { getSslPaths } from './sslhelper.js';

/**
 * Resolve the directory containing the current Node.js executable.
 *
 * @returns {string} The directory containing the Node binary
 */
function getNodeDir() {
  return dirname(process.execPath);
}

/**
 * Resolve the platform-specific Node.js library directory.
 *
 * @returns {string} Path to Node.js shared libraries
 */
function getNodeLibDir() {
  const nodeDir = getNodeDir();
  return nodeDir.replace(/bin$/, 'lib');
}



/**
 * Return the NPM ecosystem policy object.
 *
 * The policy defines the minimum required paths and hosts for
 * running npm/yarn/pnpm package managers in a sandbox.
 *
 * @returns {Object} The policy configuration
 * @returns {string[]} returns.allowHosts - Hostnames to allow network access to
 * @returns {string[]} returns.readPaths - Filesystem paths to read from
 * @returns {string[]} returns.writePaths - Filesystem paths to write to
 * @returns {Object} returns.env - Environment variables to set
 * @returns {boolean} returns.blockFork - Prevent forking new processes
 * @returns {string[]} returns.blockExec - Executables to block
 */
export function npmPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();

  return {
    /** Hostnames the package manager may connect to */
    allowHosts: [
      'registry.npmjs.org',
      'registry.yarnpkg.com',
      'cdn.jsdelivr.net',
    ],

    /** Filesystem paths to read from */
    readPaths: [
      getNodeDir(),
      getNodeLibDir(),
      ...getSslPaths(),
      join(cwd, 'package.json'),
      join(cwd, 'package-lock.json'),
      join(cwd, 'yarn.lock'),
      join(cwd, 'pnpm-lock.yaml'),
      join(cwd, '.npmrc'),
    ],

    /** Filesystem paths to write to */
    writePaths: [
      join(cwd, 'node_modules'),
      join(cwd, 'package-lock.json'),
      join(home, '.npm'),
      join(home, '.yarn'),
      join(home, '.pnpm-store'),
    ],

    /** Environment variables */
    env: {
      npm_config_loglevel: 'warn',
    },

    /** Block all forking to prevent npm from spawning subprocesses */
    blockFork: true,

    /** Block all exec to catch postinstall scripts (bun, deno, node, shells) */
    blockExec: ['*'],
  };
}

export default npmPolicy;
