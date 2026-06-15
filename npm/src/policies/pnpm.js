/**
 * PNPM ecosystem policy.
 *
 * Hardened profile for running the PNPM package manager. Based on the
 * npm policy with PNPM-specific overrides for registry and cache paths.
 *
 * @module policies/pnpm
 */

import { dirname, join } from 'node:path';
import { statSync, realpathSync } from 'node:fs';
import { getSslPaths } from './sslhelper.js';

function getNodeDir() {
  return dirname(process.execPath);
}

function getNodeLibDir() {
  const nodeDir = getNodeDir();
  const libDir = nodeDir.replace(/bin$/, 'lib');
  return join(libDir, 'node_modules');
}

export function getPnpmPaths() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const extraPaths = [];
  const paths = (process.env.PATH || '').split(process.platform === 'win32' ? ';' : ':');

  let pnpmPath = null;

  for (const p of paths) {
    const fullPath = join(p, 'pnpm');
    try {
      if (statSync(fullPath).isFile()) {
        pnpmPath = fullPath;
        break;
      }
    } catch {}
    if (process.platform === 'win32') {
      for (const ext of ['.exe', '.cmd', '.bat']) {
        try {
          if (statSync(fullPath + ext).isFile()) {
            pnpmPath = fullPath + ext;
            break;
          }
        } catch {}
      }
      if (pnpmPath) break;
    }
  }

  // Also check common PNPM_HOME or well-known locations
  if (!pnpmPath) {
    const pnpmHome = process.env.PNPM_HOME || join(home, 'Library', 'pnpm');
    const altPath = join(pnpmHome, 'pnpm');
    try {
      if (statSync(altPath).isFile()) {
        pnpmPath = altPath;
      }
    } catch {}
  }

  if (pnpmPath) {
    try {
      const realPath = realpathSync(pnpmPath);
      extraPaths.push(dirname(pnpmPath));
      extraPaths.push(pnpmPath);
      if (realPath !== pnpmPath) {
        extraPaths.push(dirname(realPath));
        extraPaths.push(realPath);
      }

      const nmIdx = pnpmPath.indexOf('node_modules');
      if (nmIdx !== -1) {
        const rootDir = pnpmPath.substring(0, nmIdx);
        if (rootDir) {
          extraPaths.push(rootDir);
        }
      }
      const realNmIdx = realPath.indexOf('node_modules');
      if (realNmIdx !== -1) {
        const realRootDir = realPath.substring(0, realNmIdx);
        if (realRootDir) {
          extraPaths.push(realRootDir);
        }
      }
    } catch {}
  }
  return extraPaths;
}

/**
 * Return the PNPM ecosystem policy object.
 *
 * @returns {Object} The policy configuration
 */
export function pnpmPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const temp = join(home, '.pnpm-store', 'tmp');

  return {
    resolveSymlinks: true,

    // 1. NETWORK RESTRICTIONS
    allowHosts: [
      'registry.npmjs.org',
    ],

    // 2. READ PATHS
    readPaths: [
      getNodeDir(),
      getNodeLibDir(),
      ...getSslPaths(),
      join(cwd, 'package.json'),
      join(cwd, 'pnpm-lock.yaml'),
      join(cwd, '.npmrc'),
      join(home, '.npmrc'),
      join(home, '.config', 'pnpm'),
      ...(process.platform === 'darwin' ? [join(home, 'Library', 'Preferences', 'pnpm')] : []),
      ...getPnpmPaths(),
    ],

    // 3. WRITE PATHS
    writePaths: [
      join(cwd, 'node_modules'),
      join(cwd, 'pnpm-lock.yaml'),
      join(home, '.pnpm-store'),

      // Cross-platform PNPM global state directories
      join(home, '.local', 'share', 'pnpm'),
      ...(process.platform === 'darwin' ? [join(home, 'Library', 'pnpm')] : []),
      ...(process.env.LOCALAPPDATA ? [join(process.env.LOCALAPPDATA, 'pnpm')] : []),

      temp,
    ],

    // 4. ENVIRONMENT CONTROLS
    env: {
      npm_config_loglevel: 'warn',
      npm_config_ignore_scripts: 'true',
    },

    // 5. EXECUTION CONTROLS
    blockFork: true,
    blockExec: ['*'],
  };
}

export default pnpmPolicy;