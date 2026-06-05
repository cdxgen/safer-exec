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
      join(cwd, 'yarn.lock'),
      join(cwd, '.npmrc'),
      join(cwd, '.yarnrc'),
      join(cwd, '.yarnrc.yml'),
    ],

    writePaths: [
      join(cwd, 'node_modules'),
      join(cwd, 'yarn.lock'),
      join(home, '.npm'),
      join(home, '.yarn'),
      join(home, '.cache', 'yarn'),
    ],

    env: {
      npm_config_loglevel: 'warn',
    },

    blockFork: true,
    blockExec: ['*'],
  };
}

export default yarnPolicy;
