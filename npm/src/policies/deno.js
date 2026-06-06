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
      // CRITICAL: Prevent Deno from hanging on interactive prompts when it
      // requests ungranted permissions (e.g., net/read/write) at runtime
      DENO_NO_PROMPT: '1',
      // Disable update checks
      DENO_NO_UPDATE_CHECK: '1',
    },

    /** Block all execution to prevent runtime escapes via Deno.Command / Deno.run */
    blockFork: true,
    blockExec: ['*'],
  };
}

export default denoPolicy;