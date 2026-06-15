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
import { getSslPaths } from './sslhelper.js';
import { execSync } from 'node:child_process';

function resolveDenoPaths(home) {
  let denoBin = '/usr/local/bin/deno';
  let denoInstall = join(home, '.deno');

  try {
    const bin = execSync('which deno', { encoding: 'utf-8' }).trim();
    if (bin) {
      denoBin = bin;
    }
  } catch {}

  if (process.env.DENO_INSTALL_ROOT) {
    denoInstall = process.env.DENO_INSTALL_ROOT;
  }

  return { denoBin, denoInstall };
}

export function denoPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const { denoBin, denoInstall } = resolveDenoPaths(home);

  return {
    allowHosts: [
      'jsr.io',
      'deno.land',
      'registry.npmjs.org',
    ],

    readPaths: [
      denoBin,
      denoInstall,
      ...getSslPaths(),
      join(cwd, 'deno.json'),
      join(cwd, 'deno.jsonc'),
    ],

    writePaths: [
      join(home, '.cache', 'deno'),
      join(cwd, 'node_modules'),
    ],

    env: {
      DENO_INSTALL_ROOT: denoInstall,
      DENO_DIR: join(home, '.cache', 'deno'),
      DENO_NO_PROMPT: '1',
      DENO_NO_UPDATE_CHECK: '1',
    },

    blockFork: true,

    denyPersistenceWrites: true,

    blockInterpreters: true,
    blockExec: ['*'],
  };
}

export default denoPolicy;