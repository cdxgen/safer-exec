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
      'github.com', // Required if fetching git dependencies via libgit2
    ],

    readPaths: [
      rustupHome,
      cargoHome,
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
      // CRITICAL: Force cargo to use internal libgit2 rather than spawning shell 'git' commands
      CARGO_NET_GIT_FETCH_WITH_CLI: 'false',
    },

    /**
     * Block all execution to prevent arbitrary code execution via build.rs
     * Ensures this policy is safely used for metadata/lockfile fetching.
     */
    blockFork: true,
    blockExec: ['*'],
  };
}

export default cargoPolicy;