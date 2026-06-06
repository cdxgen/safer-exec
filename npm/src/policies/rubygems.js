/**
 * Ruby / RubyGems / Bundler ecosystem policy.
 *
 * Hardened profile for running Ruby package managers (gem, bundler). Covers:
 * - RubyGems registry hosts
 * - Ruby standard library paths
 * - SSL certificate paths
 * - Gem cache directory isolation
 *
 * @module policies/rubygems
 */

import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { getSslPaths, isMac } from './sslhelper.js';

function resolveRubyPaths() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  return {
    rubyBin: '/usr/bin/ruby',
    rubyLib: '/usr/lib/ruby',
    rubyGemLib: isMac ? '/usr/local/lib/ruby/gems' : '/usr/lib/ruby/gems',
    // Support common Ruby version managers where standard libraries exist
    rbenv: join(home, '.rbenv'),
    rvm: join(home, '.rvm'),
    asdf: join(home, '.asdf'),
  };
}

/**
 * Return the Ruby/RubyGems/Bundler ecosystem policy object.
 *
 * @returns {Object} The policy configuration
 */
export function rubygemsPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const temp = tmpdir();
  const { rubyBin, rubyLib, rubyGemLib, rbenv, rvm, asdf } = resolveRubyPaths();

  return {
    allowHosts: [
      'rubygems.org',
      'api.rubygems.org',
      'index.rubygems.org',
      'gems.rubygems.org',
      'rubygems.global.ssl.fastly.net', // Core CDN used by rubygems.org
    ],

    readPaths: [
      rubyBin,
      rubyLib,
      rubyGemLib,
      rbenv,
      rvm,
      asdf,
      ...getSslPaths(),
      join(cwd, 'Gemfile'),
      join(cwd, 'Gemfile.lock'),
      join(cwd, '.ruby-version'), // Determines which ruby version to use
      join(cwd, '.bundle'),       // Local bundler configurations
      join(home, '.gemrc'),       // Global credentials/configs
      join(home, '.bundle'),
      temp,
    ],

    writePaths: [
      join(cwd, 'vendor'),
      join(cwd, '.bundle'),       // Bundler writes local config states here
      join(cwd, 'Gemfile.lock'),  // Bundler must be able to update lockfiles
      join(home, '.gem'),
      join(home, '.bundle'),
      join(home, '.cache', 'bundler'), // Standard bundler caching
      temp,
    ],

    env: {
      GEM_PATH: join(home, '.gem'),
      BUNDLE_PATH: join(cwd, 'vendor', 'bundle'),
    },

    // Execution controls to prevent malicious extconf.rb scripts from running.
    // NOTE: This will prevent the installation of gems requiring native C-extension compilation.
    // If you need gems like `nokogiri` or `pg`, ensure you use precompiled binaries where possible.
    blockFork: true,
    blockExec: ['*'],
  };
}

export default rubygemsPolicy;