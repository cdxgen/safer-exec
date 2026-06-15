/**
 * UV (Python) ecosystem policy.
 *
 * Hardened profile for running the uv package manager and installer. Covers:
 * - PyPI hosts
 * - UV binary detection (single static binary)
 * - Python standard library paths
 * - Virtual environment isolation
 * - Cache directory isolation
 *
 * @module policies/uv
 */

import { join } from 'node:path';
import { getSslPaths } from './sslhelper.js';
import { execSync } from 'node:child_process';

function getPythonLibPath() {
  let pythonLib = '';

  try {
    const pythonBin = process.env.UV_PYTHON || execSync('which python3', { encoding: 'utf-8' }).trim();
    if (pythonBin) {
      pythonLib = execSync(
        `${pythonBin} -c "import sys; print([p for p in sys.path if '/lib/python' in p or '/Lib' in p][0] if any('/lib/python' in p or '/Lib' in p for p in sys.path) else '')"`,
        { encoding: 'utf-8' }
      ).trim();
    }
  } catch {}

  return pythonLib;
}

function resolveUvPaths(home) {
  let uvBin = 'uv';

  try {
    const bin = execSync('which uv', { encoding: 'utf-8' }).trim();
    if (bin) {
      uvBin = bin;
    }
  } catch {}

  const pythonLib = getPythonLibPath();

  return { uvBin, pythonLib };
}

/**
 * Return the UV ecosystem policy object.
 *
 * @returns {Object} The policy configuration
 */
export function uvPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const { uvBin, pythonLib } = resolveUvPaths(home);

  const readPaths = [
    uvBin,
    ...getSslPaths(),
    join(cwd, 'pyproject.toml'),
    join(cwd, 'uv.lock'),
    join(cwd, '.python-version'),
  ];

  if (pythonLib) {
    readPaths.push(pythonLib);
  }

  return {
    allowHosts: [
      'pypi.org',
      'files.pythonhosted.org',
      'github.com',
    ],

    readPaths,

    writePaths: [
      join(cwd, '.venv'),
      join(cwd, 'uv.lock'),
      join(cwd, '__pycache__'),
      join(home, '.cache', 'uv'),
    ],

    env: {
      UV_NO_SYNC: '0',
      UV_LINK_MODE: 'copy',
      PYTHONUNBUFFERED: '1',
    },

    blockFork: true,

    denyPersistenceWrites: true,
    blockExec: ['*'],
  };
}

export default uvPolicy;
