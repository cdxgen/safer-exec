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

/**
 * Return the Rust/Cargo ecosystem policy object.
 *
 * @returns {Object} The policy configuration
 */
export function cargoPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const { rustupHome, cargoHome } = resolveRustPaths();

  return {
    allowHosts: [
      'crates.io',
      'static.crates.io',
      'docs.rs',
      'rust-lang.github.io',
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
    },
  };
}

export default cargoPolicy;
