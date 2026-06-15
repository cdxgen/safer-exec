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

import { execSync } from 'node:child_process';

function getPythonPaths() {
  let pythonBin = '/usr/bin/python3';
  let pythonLib = isMac ? '/usr/local/lib/python3.*' : '/usr/lib/python3';

  try {
    const bin = execSync('which python3', { encoding: 'utf-8' }).trim();
    if (bin) {
      pythonBin = bin;
      const lib = execSync(`${pythonBin} -c "import sys; print([p for p in sys.path if 'lib/python' in p][0])"`, { encoding: 'utf-8' }).trim();
      if (lib) {
        pythonLib = lib;
      }
    }
  } catch (e) {
    // Fall back to defaults if lookup fails
  }

  return { pythonBin, pythonLib };
}

export function pypiPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const { pythonBin, pythonLib } = getPythonPaths();

  return {
    allowHosts: [
      'pypi.org',
      'files.pythonhosted.org',
      // Removed www.python.org - completely unnecessary for pip installations
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
      // CRITICAL: Force Pip to only download pre-compiled Wheels.
      // This categorically prevents arbitrary code execution from malicious `setup.py` scripts.
      PIP_ONLY_BINARY: ':all:',
    },

    /** OS-level blocking to prevent Python's `subprocess` or `os.system` */
    blockFork: true,
    denyPersistenceWrites: true,
    // '*' blocks SYS_EXECVE via seccomp for child processes.
    // Shell names block the initial command in execCommand, preventing shell-based
    // persistence attacks (e.g. 'echo malware >> ~/.bashrc') in reduced-isolation mode
    // where there is no filesystem namespace to prevent writes to dotfiles.
    blockExec: ['*', 'sh', 'bash', 'dash', 'zsh', 'fish', 'ksh', 'tcsh', 'csh'],
  };
}

export default pypiPolicy;