/**
 * Yarn ecosystem policy.
 *
 * Hardened profile for running the Yarn package manager. Based on the
 * npm policy with Yarn-specific overrides for registry and cache paths.
 *
 * @module policies/yarn
 */

import { dirname, join } from 'node:path';
import { getSslPaths } from './sslhelper.js';

function getNodeDir() {
  return dirname(process.execPath);
}

function getNodeLibDir() {
  const nodeDir = getNodeDir();
  const libDir = nodeDir.replace(/bin$/, 'lib');
  return join(libDir, 'node_modules');
}

/**
 * Return the Yarn ecosystem policy object.
 *
 * @returns {Object} The policy configuration
 */
export function yarnPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();

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
      join(cwd, '.yarn'),
      join(home, '.npmrc'),
      join(home, '.yarnrc'),
      join(home, '.yarnrc.yml'),
    ],

    writePaths: [
      join(cwd, 'node_modules'),
      join(cwd, 'yarn.lock'),
      join(cwd, '.yarn'),
      join(cwd, '.pnp.cjs'),
      join(cwd, '.pnp.loader.mjs'),

      // Global caching
      join(home, '.yarn'),
      join(home, '.cache', 'yarn'),
      ...(process.platform === 'darwin' ? [join(home, 'Library', 'Caches', 'Yarn')] : []),
      ...(process.env.LOCALAPPDATA ? [join(process.env.LOCALAPPDATA, 'Yarn')] : []),
    ],

    env: {
      npm_config_loglevel: 'warn',
      npm_config_ignore_scripts: 'true',
      YARN_ENABLE_SCRIPTS: 'false',
    },

    blockFork: true,
    blockExec: ['*'],
  };
}

export default yarnPolicy;