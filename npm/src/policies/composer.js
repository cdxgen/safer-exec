/**
 * PHP / Composer ecosystem policy.
 *
 * Hardened profile for running PHP package manager (Composer). Covers:
 * - Packagist registry hosts
 * - PHP binary detection
 * - SSL certificate paths
 * - Composer cache directory isolation
 *
 * @module policies/composer
 */

import { join } from 'node:path';
import { getSslPaths, isMac } from './sslhelper.js';



function resolvePhpPaths() {
  if (isMac) {
    return {
      phpBin: '/usr/bin/php',
      phpLib: '/usr/local/lib/php',
      phpExtDir: '/usr/local/lib/php/extensions',
    };
  }
  return {
    phpBin: '/usr/bin/php',
    phpLib: '/usr/lib/php',
    phpExtDir: '/usr/lib/php/extensions',
  };
}

/**
 * Return the PHP/Composer ecosystem policy object.
 *
 * @returns {Object} The policy configuration
 */
export function composerPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const { phpBin, phpLib, phpExtDir } = resolvePhpPaths();

  return {
    allowHosts: [
      'packagist.org',
      'repo.packagist.org',
      'api.github.com',
      'composer.github.com',
    ],

    readPaths: [
      phpBin,
      phpLib,
      phpExtDir,
      ...getSslPaths(),
      join(cwd, 'composer.json'),
      join(cwd, 'composer.lock'),
    ],

    writePaths: [
      join(cwd, 'vendor'),
      join(home, '.config', 'composer'),
      join(home, '.composer'),
    ],

    env: {
      COMPOSER_HOME: join(home, '.config', 'composer'),
    },
  };
}

export default composerPolicy;
