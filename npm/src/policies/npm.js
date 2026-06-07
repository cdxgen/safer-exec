/**
 * NPM / Yarn / PNPM ecosystem policy.
 *
 * Hardened profile for running JavaScript package managers. Covers:
 * - NPM registry hosts
 * - Yarn registry hosts
 * - PNPM registry hosts
 * - Node binary detection
 * - SSL certificate paths
 * - Cache directory isolation
 *
 * @module policies/npm
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

export function npmPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();

  return {
    allowHosts: [
      'registry.npmjs.org',
      'registry.yarnpkg.com',
      // 'cdn.jsdelivr.net', // Removed: Reduce surface. Usually not needed for strict dependency resolution.
    ],

    readPaths: [
      getNodeDir(),
      getNodeLibDir(),
      ...getSslPaths(),
      join(cwd, 'package.json'),
      join(cwd, 'package-lock.json'),
      join(cwd, 'yarn.lock'),
      join(cwd, 'pnpm-lock.yaml'),
      join(cwd, '.npmrc'),
    ],

    writePaths: [
      join(cwd, 'node_modules'),
      join(cwd, 'package-lock.json'),
      join(cwd, 'yarn.lock'),
      join(cwd, 'pnpm-lock.yaml'),
      join(home, '.npm'),
      join(home, '.yarn'),
      join(home, '.pnpm-store'),
    ],

    env: {
      npm_config_loglevel: 'warn',
      // CRITICAL DEFENSE IN DEPTH: Natively instruct package managers to skip execution,
      // preventing sandbox crash loops or deadlock hangs when fork is blocked.
      npm_config_ignore_scripts: 'true',
      npm_config_audit: 'false',
      npm_config_fund: 'false',
      npm_config_update_notifier: 'false',
      npm_config_telemetry: 'false',
    },

    /** Block all forking to strictly prevent OS-level shell spawning */
    blockFork: true,
    // '*' blocks SYS_EXECVE via seccomp for child processes.
    // Compiler names block the initial command in execCommand (covers reduced-isolation mode
    // where there is no filesystem namespace to prevent gcc/clang from being invoked directly).
    blockExec: ['*', 'gcc', 'g++', 'clang', 'clang++', 'cc', 'c++', 'ld', 'as', 'make', 'cmake', 'ninja'],
  };
}

export default npmPolicy;