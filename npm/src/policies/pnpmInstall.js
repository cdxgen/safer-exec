/**
 * PNPM Install policy.
 *
 * Hardened policy specifically designed for running pnpm install commands.
 * Extends the base pnpm policy to allow execution and project directory writes.
 *
 * @module policies/pnpmInstall
 */

import { pnpmPolicy } from './pnpm.js';

/**
 * Return the PNPM install policy configuration.
 *
 * @returns {Object} The policy configuration
 */
export function pnpmInstallPolicy() {
  const base = pnpmPolicy();
  const cwd = process.cwd();

  // Extend readPaths with standard system paths and full project directory read access
  const readPaths = new Set([
    ...base.readPaths,
    cwd,
    '/usr',
    '/opt',
    '/etc',
  ]);

  // Extend writePaths with full project directory write access
  const writePaths = new Set([
    ...base.writePaths,
    cwd,
  ]);

  return {
    ...base,
    readPaths: Array.from(readPaths),
    writePaths: Array.from(writePaths),
    blockFork: false,
    blockExec: [],
  };
}

export default pnpmInstallPolicy;
