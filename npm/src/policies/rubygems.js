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
import { getSslPaths } from './sslhelper.js';
import { execSync } from 'node:child_process';

function resolveRubyPaths() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  let rubyBin = '/usr/bin/ruby';
  let rubyLib = '/usr/lib/ruby';
  let rubyGemLib = '/usr/lib/ruby/gems';
  let gemHome = join(home, '.gem');

  try {
    const bin = execSync('which ruby', { encoding: 'utf-8' }).trim();
    if (bin) rubyBin = bin;
    const ver = execSync(`${rubyBin} -e 'print RbConfig::CONFIG["ruby_version"]'`, { encoding: 'utf-8' }).trim();
    if (ver) rubyLib = join('/usr/lib/ruby', ver);
    const gemdir = execSync(`${rubyBin} -e 'print Gem.default_dir'`, { encoding: 'utf-8' }).trim();
    if (gemdir) rubyGemLib = gemdir;
    const gemhome = execSync(`${rubyBin} -e 'print Gem.user_dir'`, { encoding: 'utf-8' }).trim();
    if (gemhome) gemHome = gemhome;
  } catch {}

  return { rubyBin, rubyLib, rubyGemLib, gemHome };
}

/**
 * Return the Ruby/RubyGems/Bundler ecosystem policy object.
 *
 * @returns {Object} The policy configuration
 */
export function rubygemsPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const { rubyBin, rubyLib, rubyGemLib, gemHome } = resolveRubyPaths();

  return {
    allowHosts: [
      'rubygems.org',
      'api.rubygems.org',
      'index.rubygems.org',
      'gems.rubygems.org',
      'rubygems.global.ssl.fastly.net',
    ],

    readPaths: [
      rubyBin,
      rubyLib,
      rubyGemLib,
      gemHome,
      ...getSslPaths(),
      join(cwd, 'Gemfile'),
      join(cwd, 'Gemfile.lock'),
      join(cwd, '.ruby-version'),
      join(cwd, '.bundle'),
      join(home, '.gemrc'),
      join(home, '.bundle'),
    ],

    writePaths: [
      join(cwd, 'vendor'),
      join(cwd, '.bundle'),
      join(cwd, 'Gemfile.lock'),
      gemHome,
      join(home, '.bundle'),
      join(home, '.cache', 'bundler'),
    ],

    env: {
      GEM_PATH: gemHome,
      BUNDLE_PATH: join(cwd, 'vendor', 'bundle'),
    },

    blockFork: true,
    blockExec: ['*'],
  };
}

export default rubygemsPolicy;