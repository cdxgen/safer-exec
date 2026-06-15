/**
 * Go / Go modules ecosystem policy.
 *
 * Hardened profile for running Go tools and module downloads. Covers:
 * - Go module proxy hosts
 * - Go toolchain detection
 * - SSL certificate paths
 * - Go module cache isolation
 *
 * @module policies/gomod
 */

import { join } from 'node:path';
import { getSslPaths } from './sslhelper.js';

function resolveGoPaths() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const goPath = process.env.GOPATH || join(home, 'go');
  const goRoot = process.env.GOROOT || '/usr/local/go';
  return { goPath, goRoot };
}

export function gomodPolicy() {
  const cwd = process.cwd();
  const { goPath, goRoot } = resolveGoPaths();

  return {
    allowHosts: [
      'proxy.golang.org',
      'sum.golang.org',
      'github.com',
      'golang.org',
    ],

    readPaths: [
      goRoot,
      ...getSslPaths(),
      join(cwd, 'go.mod'),
      join(cwd, 'go.sum'),
    ],

    writePaths: [
      join(goPath, 'pkg', 'mod'),
      join(goPath, 'bin'),
      join(cwd, 'bin'),
    ],

    env: {
      GOPATH: goPath,
      GOROOT: goRoot,
      GOFLAGS: '-mod=mod',
      GOPROXY: 'https://proxy.golang.org,direct',
      GOSUMDB: 'sum.golang.org',
      CGO_ENABLED: '0',
    },

    blockFork: true,
    blockExec: ['*'],
  };
}

export default gomodPolicy;