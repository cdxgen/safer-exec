/**
 * Deno ecosystem policy.
 *
 * Hardened profile for running the Deno runtime. Covers:
 * - Deno registry hosts
 * - Deno binary detection
 * - SSL certificate paths
 * - Deno cache directory isolation
 *
 * @module policies/deno
 */

import { join } from 'node:path';
import { getSslPaths, isMac } from './sslhelper.js';



function resolveDenoPaths() {
  if (isMac) {
    return {
      denoBin: '/usr/local/bin/deno',
      denoLib: '/usr/local/lib',
    };
  }
  return {
    denoBin: '/usr/bin/deno',
    denoLib: '/usr/lib',
  };
}

/**
 * Return the Deno ecosystem policy object.
 *
 * @returns {Object} The policy configuration
 */
export function denoPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const { denoBin, denoLib } = resolveDenoPaths();

  return {
    allowHosts: [
      'jsr.io',
      'cdn.jsdelivr.net',
      'deno.land',
      'registry.npmjs.org',
    ],

    readPaths: [
      denoBin,
      denoLib,
      ...getSslPaths(),
      join(cwd, 'deno.json'),
      join(cwd, 'deno.jsonc'),
    ],

    writePaths: [
      join(home, '.cache', 'deno'),
      join(cwd, 'node_modules'),
    ],

    env: {
      DENO_INSTALL_ROOT: join(home, '.deno'),
      DENO_DIR: join(home, '.cache', 'deno'),
    },
  };
}

export default denoPolicy;
