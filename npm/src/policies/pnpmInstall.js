/**
 * PNPM Install policy.
 *
 * Hardened policy specifically designed for running pnpm install commands.
 * Extends the base pnpm policy to allow execution and project directory writes.
 *
 * @module policies/pnpmInstall
 */

import { join } from 'node:path';
import { pnpmPolicy } from './pnpm.js';
import { getSslPaths } from './sslhelper.js';

/**
 * Return the PNPM install policy configuration.
 *
 * @returns {Object} The policy configuration
 */
export function pnpmInstallPolicy() {
  const base = pnpmPolicy();
  const cwd = process.cwd();

  const readPaths = new Set([
    ...base.readPaths,
    cwd,
  ]);

  const writePaths = new Set([
    ...base.writePaths,
    cwd,
  ]);

  return {
    ...base,
    readPaths: Array.from(readPaths),
    writePaths: Array.from(writePaths),
    blockFork: false,
    denyPersistenceWrites: true,
    blockInterpreters: true,
    blockExec: [],
  };
}

export default pnpmInstallPolicy;
