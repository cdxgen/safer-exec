/**
 * Python / PyPI ecosystem policy.
 *
 * Hardened profile for running Python package managers (pip, uv). Covers:
 * - PyPI hosts
 * - Python standard library paths
 * - SSL certificate paths
 * - Virtual environment isolation
 * - Cache directory isolation
 *
 * @module policies/pypi
 */

import { join } from 'node:path';
import { getSslPaths, isMac } from './sslhelper.js';



function getPythonPaths() {
  if (isMac) {
    return {
      pythonBin: '/usr/bin/python3',
      pythonLib: '/usr/local/lib/python3.*',
    };
  }
  return {
    pythonBin: '/usr/bin/python3',
    pythonLib: '/usr/lib/python3',
  };
}

/**
 * Return the Python/PyPI ecosystem policy object.
 *
 * @returns {Object} The policy configuration
 */
export function pypiPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const { pythonBin, pythonLib } = getPythonPaths();

  return {
    allowHosts: [
      'pypi.org',
      'files.pythonhosted.org',
      'www.python.org',
    ],

    readPaths: [
      pythonBin,
      pythonLib,
      ...getSslPaths(),
      join(cwd, 'requirements.txt'),
      join(cwd, 'pyproject.toml'),
      join(cwd, 'setup.py'),
      join(cwd, 'setup.cfg'),
    ],

    writePaths: [
      join(cwd, '.venv'),
      join(cwd, '__pycache__'),
      join(cwd, 'build'),
      join(cwd, 'dist'),
      join(home, '.cache', 'pip'),
      join(home, '.local', 'lib', 'python3'),
    ],

    env: {
      PIP_NO_CACHE_DIR: '0',
      PIP_DISABLE_PIP_VERSION_CHECK: '1',
      PYTHONUNBUFFERED: '1',
    },
  };
}

export default pypiPolicy;
