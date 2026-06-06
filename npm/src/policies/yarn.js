/**
 * Yarn ecosystem policy.
 *
 * Hardened profile for running the Yarn package manager. Based on the
 * npm policy with Yarn-specific overrides for registry and cache paths.
 *
 * @module policies/yarn
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
 * Return the Yarn ecosystem policy object.
 *
 * @returns {Object} The policy configuration
 */
export function yarnPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const temp = tmpdir();

  return {
    allowHosts: [
      'registry.npmjs.org',
      'registry.yarnpkg.com',
    ],

    readPaths: [
      getNodeDir(),
      getNodeLibDir(),
      ...getSslPaths(),
      join(cwd, 'package.json'),
      join(cwd, 'yarn.lock'),
      join(cwd, '.npmrc'),
      join(cwd, '.yarnrc'),
      join(cwd, '.yarnrc.yml'),
      join(cwd, '.yarn'),          // Support for modern Yarn Berry
      join(home, '.npmrc'),        // Often contains required registry auth tokens
      join(home, '.yarnrc'),
      join(home, '.yarnrc.yml'),
      temp,                        // Required for extracting tarballs safely
    ],

    writePaths: [
      join(cwd, 'node_modules'),
      join(cwd, 'yarn.lock'),
      join(cwd, '.yarn'),          // Local Yarn Berry cache and install state
      join(cwd, '.pnp.cjs'),       // Yarn Berry Plug'n'Play loader
      join(cwd, '.pnp.loader.mjs'),

      // Global caching
      join(home, '.yarn'),
      join(home, '.cache', 'yarn'),
      ...(process.platform === 'darwin' ? [join(home, 'Library', 'Caches', 'Yarn')] : []),
      ...(process.env.LOCALAPPDATA ? [join(process.env.LOCALAPPDATA, 'Yarn')] : []),

      temp,
    ],

    env: {
      npm_config_loglevel: 'warn',
      npm_config_ignore_scripts: 'true', // Hardening for Yarn 1.x
      YARN_ENABLE_SCRIPTS: 'false',      // Hardening for Yarn Berry (v2+)
    },

    blockFork: true,
    blockExec: ['*'],
  };
}

export default yarnPolicy;