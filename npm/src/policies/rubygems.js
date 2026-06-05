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
import { getSslPaths, isMac } from './sslhelper.js';



function resolveRubyPaths() {
  if (isMac) {
    return {
      rubyBin: '/usr/bin/ruby',
      rubyLib: '/usr/lib/ruby',
      rubyGemLib: '/usr/local/lib/ruby/gems',
    };
  }
  return {
    rubyBin: '/usr/bin/ruby',
    rubyLib: '/usr/lib/ruby',
    rubyGemLib: '/usr/lib/ruby/gems',
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
  const { rubyBin, rubyLib, rubyGemLib } = resolveRubyPaths();

  return {
    allowHosts: [
      'rubygems.org',
      'api.rubygems.org',
      'gems.rubygems.org',
      's3.amazonaws.com',
    ],

    readPaths: [
      rubyBin,
      rubyLib,
      rubyGemLib,
      ...getSslPaths(),
      join(cwd, 'Gemfile'),
      join(cwd, 'Gemfile.lock'),
    ],

    writePaths: [
      join(cwd, 'vendor'),
      join(home, '.gem'),
      join(home, '.bundle'),
    ],

    env: {
      GEM_PATH: join(home, '.gem'),
      BUNDLE_PATH: join(cwd, 'vendor', 'bundle'),
    },
  };
}

export default rubygemsPolicy;
