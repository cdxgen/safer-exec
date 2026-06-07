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

import { execSync } from 'node:child_process';

function resolvePhpPaths() {
  let phpBin = '/usr/bin/php';
  let phpLib = isMac ? '/usr/local/lib/php' : '/usr/lib/php';
  let phpExtDir = isMac ? '/usr/local/lib/php/extensions' : '/usr/lib/php/extensions';

  try {
    const bin = execSync('which php', { encoding: 'utf-8' }).trim();
    if (bin) {
      phpBin = bin;
      const extDir = execSync(`${phpBin} -r "echo ini_get('extension_dir');"`, { encoding: 'utf-8' }).trim();
      if (extDir) {
        phpExtDir = extDir;
      }
    }
  } catch (e) {
    // Fall back to defaults if lookup fails
  }

  return { phpBin, phpLib, phpExtDir };
}

export function composerPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const { phpBin, phpLib, phpExtDir } = resolvePhpPaths();

  return {
    allowHosts: [
      'packagist.org',
      'repo.packagist.org',
      'api.github.com',
      'codeload.github.com', // Required for GitHub zipball downloads via Composer
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
      // CRITICAL: Disable all custom composer lifecycle scripts
      COMPOSER_DISABLE_SCRIPTS: '1',
      // CRITICAL: Disable third-party plugins executing inside the Composer context
      COMPOSER_NO_PLUGINS: '1',
      // Prevent interactive prompt hangs in headless environments
      COMPOSER_NO_INTERACTION: '1',
      // Drop superuser usage warnings
      COMPOSER_ALLOW_SUPERUSER: '0',
    },

    /** OS-level blocking to prevent composer from spawning child processes */
    blockFork: true,
    blockExec: ['*'],
  };
}

export default composerPolicy;