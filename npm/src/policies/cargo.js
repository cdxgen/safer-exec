/**
 * Rust / Cargo ecosystem policy.
 *
 * Hardened profile for running the Rust package manager. Covers:
 * - Crates.io hosts
 * - Rust toolchain detection
 * - SSL certificate paths
 * - Build directory isolation
 * - Cache directory isolation
 *
 * @module policies/cargo
 */

import { join } from 'node:path';
import { getSslPaths } from './sslhelper.js';

function resolveRustPaths() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const rustupHome = process.env.RUSTUP_HOME || join(home, '.rustup');
  const cargoHome = process.env.CARGO_HOME || join(home, '.cargo');
  return { rustupHome, cargoHome };
}

export function cargoPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const { rustupHome, cargoHome } = resolveRustPaths();

  return {
    allowHosts: [
      'crates.io',
      'static.crates.io',
      'index.crates.io',
      'github.com',
    ],

    readPaths: [
      join(cargoHome, 'registry'),
      join(cargoHome, 'bin'),
      join(rustupHome, 'toolchains'),
      ...getSslPaths(),
      join(cwd, 'Cargo.toml'),
      join(cwd, 'Cargo.lock'),
    ],

    writePaths: [
      join(cwd, 'target'),
      join(cargoHome, 'registry'),
      join(rustupHome, 'toolchains'),
    ],

    env: {
      CARGO_TERM_COLOR: 'auto',
      RUSTUP_TOOLCHAIN: 'stable',
      CARGO_NET_GIT_FETCH_WITH_CLI: 'false',
    },

    blockFork: true,

    denyPersistenceWrites: true,

    blockInterpreters: true,
    blockExec: ['*'],
  };
}

export default cargoPolicy;