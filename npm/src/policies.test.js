/**
 * Unit tests for the policy modules.
 *
 * Tests that each policy returns valid configuration with the
 * expected hosts, paths, and environment variables.
 *
 * @module policies_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { npmPolicy } from './policies/npm.js';
import { pypiPolicy } from './policies/pypi.js';
import { mavenPolicy } from './policies/maven.js';
import { cargoPolicy } from './policies/cargo.js';
import { rubygemsPolicy } from './policies/rubygems.js';
import { composerPolicy } from './policies/composer.js';
import { denoPolicy } from './policies/deno.js';
import { gomodPolicy } from './policies/gomod.js';
import { bunPolicy } from './policies/bun.js';

describe('policies', () => {
  describe('npmPolicy', () => {
    it('should return a valid policy object', () => {
      const policy = npmPolicy();
      strict.ok(policy.allowHosts, 'should have allowHosts');
      strict.ok(policy.readPaths, 'should have readPaths');
      strict.ok(policy.writePaths, 'should have writePaths');
      strict.ok(policy.env, 'should have env');
    });

    it('should include NPM registry hosts', () => {
      const policy = npmPolicy();
      strict.ok(
        policy.allowHosts.includes('registry.npmjs.org'),
        'should include NPM registry'
      );
      strict.ok(
        policy.allowHosts.includes('registry.yarnpkg.com'),
        'should include Yarn registry'
      );
    });

    it('should include SSL certificate paths', () => {
      const policy = npmPolicy();
      strict.ok(
        policy.readPaths.includes('/etc/ssl/certs'),
        'should include SSL certs'
      );
    });

    it('should include Node.js binary paths', () => {
      const policy = npmPolicy();
      strict.ok(
        policy.readPaths.some((p) => p.includes('node') || p.includes(process.execPath)),
        'should include Node.js paths'
      );
    });

    it('should set npm_config_loglevel to warn', () => {
      const policy = npmPolicy();
      strict.equal(policy.env.npm_config_loglevel, 'warn');
    });
  });

  describe('pypiPolicy', () => {
    it('should return a valid policy object', () => {
      const policy = pypiPolicy();
      strict.ok(policy.allowHosts, 'should have allowHosts');
      strict.ok(policy.readPaths, 'should have readPaths');
      strict.ok(policy.writePaths, 'should have writePaths');
      strict.ok(policy.env, 'should have env');
    });

    it('should include PyPI hosts', () => {
      const policy = pypiPolicy();
      strict.ok(
        policy.allowHosts.includes('pypi.org'),
        'should include PyPI'
      );
      strict.ok(
        policy.allowHosts.includes('files.pythonhosted.org'),
        'should include Python files host'
      );
    });

    it('should include Python library paths', () => {
      const policy = pypiPolicy();
      strict.ok(
        policy.readPaths.some((p) => p.includes('python')),
        'should include Python paths'
      );
    });

    it('should include virtual env write paths', () => {
      const policy = pypiPolicy();
      strict.ok(
        policy.writePaths.some((p) => p.includes('.venv')),
        'should include .venv write path'
      );
    });
  });

  describe('mavenPolicy', () => {
    it('should return a valid policy object', () => {
      const policy = mavenPolicy();
      strict.ok(policy.allowHosts, 'should have allowHosts');
      strict.ok(policy.readPaths, 'should have readPaths');
      strict.ok(policy.writePaths, 'should have writePaths');
      strict.ok(policy.env, 'should have env');
    });

    it('should include Maven Central hosts', () => {
      const policy = mavenPolicy();
      strict.ok(
        policy.allowHosts.includes('repo.maven.apache.org'),
        'should include Maven Central'
      );
      strict.ok(
        policy.allowHosts.includes('repo1.maven.org'),
        'should include Maven mirror'
      );
    });

    it('should include Gradle hosts', () => {
      const policy = mavenPolicy();
      strict.ok(
        policy.allowHosts.includes('services.gradle.org'),
        'should include Gradle services'
      );
    });

    it('should include Maven cache write paths', () => {
      const policy = mavenPolicy();
      strict.ok(
        policy.writePaths.some((p) => p.includes('.m2')),
        'should include .m2 cache path'
      );
    });
  });

  describe('cargoPolicy', () => {
    it('should return a valid policy object', () => {
      const policy = cargoPolicy();
      strict.ok(policy.allowHosts, 'should have allowHosts');
      strict.ok(policy.readPaths, 'should have readPaths');
      strict.ok(policy.writePaths, 'should have writePaths');
      strict.ok(policy.env, 'should have env');
    });

    it('should include Crates.io hosts', () => {
      const policy = cargoPolicy();
      strict.ok(
        policy.allowHosts.includes('crates.io'),
        'should include Crates.io'
      );
      strict.ok(
        policy.allowHosts.includes('static.crates.io'),
        'should include static Crates.io'
      );
    });

    it('should include Rust toolchain paths', () => {
      const policy = cargoPolicy();
      strict.ok(
        policy.readPaths.some((p) => p.includes('rustup') || p.includes('cargo')),
        'should include Rust toolchain paths'
      );
    });

    it('should include target directory write paths', () => {
      const policy = cargoPolicy();
      strict.ok(
        policy.writePaths.some((p) => p.includes('target')),
        'should include target directory'
      );
    });
  });

  describe('rubygemsPolicy', () => {
    it('should return a valid policy object', () => {
      const policy = rubygemsPolicy();
      strict.ok(policy.allowHosts, 'should have allowHosts');
      strict.ok(policy.readPaths, 'should have readPaths');
      strict.ok(policy.writePaths, 'should have writePaths');
      strict.ok(policy.env, 'should have env');
    });

    it('should include RubyGems hosts', () => {
      const policy = rubygemsPolicy();
      strict.ok(
        policy.allowHosts.includes('rubygems.org'),
        'should include RubyGems'
      );
      strict.ok(
        policy.allowHosts.includes('api.rubygems.org'),
        'should include API host'
      );
    });

    it('should include Ruby library paths', () => {
      const policy = rubygemsPolicy();
      strict.ok(
        policy.readPaths.some((p) => p.includes('ruby')),
        'should include Ruby paths'
      );
    });

    it('should include gem cache write paths', () => {
      const policy = rubygemsPolicy();
      strict.ok(
        policy.writePaths.some((p) => p.includes('.gem')),
        'should include .gem cache path'
      );
    });

    it('should set GEM_PATH env var', () => {
      const policy = rubygemsPolicy();
      strict.ok(
        policy.env.GEM_PATH,
        'should set GEM_PATH'
      );
    });

    it('should set BUNDLE_PATH env var', () => {
      const policy = rubygemsPolicy();
      strict.ok(
        policy.env.BUNDLE_PATH,
        'should set BUNDLE_PATH'
      );
    });
  });

  describe('composerPolicy', () => {
    it('should return a valid policy object', () => {
      const policy = composerPolicy();
      strict.ok(policy.allowHosts, 'should have allowHosts');
      strict.ok(policy.readPaths, 'should have readPaths');
      strict.ok(policy.writePaths, 'should have writePaths');
      strict.ok(policy.env, 'should have env');
    });

    it('should include Packagist hosts', () => {
      const policy = composerPolicy();
      strict.ok(
        policy.allowHosts.includes('packagist.org'),
        'should include Packagist'
      );
      strict.ok(
        policy.allowHosts.includes('repo.packagist.org'),
        'should include Packagist repo'
      );
    });

    it('should include PHP library paths', () => {
      const policy = composerPolicy();
      strict.ok(
        policy.readPaths.some((p) => p.includes('php')),
        'should include PHP paths'
      );
    });

    it('should include vendor write paths', () => {
      const policy = composerPolicy();
      strict.ok(
        policy.writePaths.some((p) => p.includes('vendor')),
        'should include vendor directory'
      );
    });

    it('should set COMPOSER_HOME env var', () => {
      const policy = composerPolicy();
      strict.ok(
        policy.env.COMPOSER_HOME,
        'should set COMPOSER_HOME'
      );
    });
  });

  describe('denoPolicy', () => {
    it('should return a valid policy object', () => {
      const policy = denoPolicy();
      strict.ok(policy.allowHosts, 'should have allowHosts');
      strict.ok(policy.readPaths, 'should have readPaths');
      strict.ok(policy.writePaths, 'should have writePaths');
      strict.ok(policy.env, 'should have env');
    });

    it('should include Deno.land hosts', () => {
      const policy = denoPolicy();
      strict.ok(
        policy.allowHosts.includes('deno.land'),
        'should include Deno.land'
      );
      strict.ok(
        policy.allowHosts.includes('jsr.io'),
        'should include JSR'
      );
    });

    it('should include Deno cache write paths', () => {
      const policy = denoPolicy();
      strict.ok(
        policy.writePaths.some((p) => p.includes('deno') || p.includes('.cache')),
        'should include Deno cache path'
      );
    });

    it('should set DENO_DIR env var', () => {
      const policy = denoPolicy();
      strict.ok(
        policy.env.DENO_DIR,
        'should set DENO_DIR'
      );
    });
  });

  describe('gomodPolicy', () => {
    it('should return a valid policy object', () => {
      const policy = gomodPolicy();
      strict.ok(policy.allowHosts, 'should have allowHosts');
      strict.ok(policy.readPaths, 'should have readPaths');
      strict.ok(policy.writePaths, 'should have writePaths');
      strict.ok(policy.env, 'should have env');
    });

    it('should include Go module proxy hosts', () => {
      const policy = gomodPolicy();
      strict.ok(
        policy.allowHosts.includes('proxy.golang.org'),
        'should include Go proxy'
      );
      strict.ok(
        policy.allowHosts.includes('sum.golang.org'),
        'should include Go sum checker'
      );
    });

    it('should include Go module cache write paths', () => {
      const policy = gomodPolicy();
      strict.ok(
        policy.writePaths.some((p) => p.includes('pkg') || p.includes('mod')),
        'should include module cache path'
      );
    });

    it('should set GOPATH env var', () => {
      const policy = gomodPolicy();
      strict.ok(
        policy.env.GOPATH,
        'should set GOPATH'
      );
    });

    it('should set GOROOT env var', () => {
      const policy = gomodPolicy();
      strict.ok(
        policy.env.GOROOT,
        'should set GOROOT'
      );
    });
  });

  describe('bunPolicy', () => {
    it('should return a valid policy object', () => {
      const policy = bunPolicy();
      strict.ok(policy.allowHosts, 'should have allowHosts');
      strict.ok(policy.readPaths, 'should have readPaths');
      strict.ok(policy.writePaths, 'should have writePaths');
      strict.ok(policy.env, 'should have env');
    });

    it('should include NPM registry hosts', () => {
      const policy = bunPolicy();
      strict.ok(
        policy.allowHosts.includes('registry.npmjs.org'),
        'should include NPM registry'
      );
      strict.ok(
        policy.allowHosts.includes('jsr.io'),
        'should include JSR'
      );
    });

    it('should include Bun cache write paths', () => {
      const policy = bunPolicy();
      strict.ok(
        policy.writePaths.some((p) => p.includes('.bun') || p.includes('cache')),
        'should include Bun cache path'
      );
    });

    it('should set BUN_INSTALL env var', () => {
      const policy = bunPolicy();
      strict.ok(
        policy.env.BUN_INSTALL,
        'should set BUN_INSTALL'
      );
    });
  });

  describe('policy defaults', () => {
    it('all policies should have non-empty allowHosts', () => {
      const policies = [
        npmPolicy, pypiPolicy, mavenPolicy, cargoPolicy,
        rubygemsPolicy, composerPolicy, denoPolicy, gomodPolicy, bunPolicy,
      ];
      for (const policyFn of policies) {
        const policy = policyFn();
        strict.ok(
          policy.allowHosts.length > 0,
          `${policyFn.name} should have allowHosts`
        );
      }
    });

    it('all policies should have non-empty readPaths', () => {
      const policies = [
        npmPolicy, pypiPolicy, mavenPolicy, cargoPolicy,
        rubygemsPolicy, composerPolicy, denoPolicy, gomodPolicy, bunPolicy,
      ];
      for (const policyFn of policies) {
        const policy = policyFn();
        strict.ok(
          policy.readPaths.length > 0,
          `${policyFn.name} should have readPaths`
        );
      }
    });

    it('all policies should have non-empty writePaths', () => {
      const policies = [
        npmPolicy, pypiPolicy, mavenPolicy, cargoPolicy,
        rubygemsPolicy, composerPolicy, denoPolicy, gomodPolicy, bunPolicy,
      ];
      for (const policyFn of policies) {
        const policy = policyFn();
        strict.ok(
          policy.writePaths.length > 0,
          `${policyFn.name} should have writePaths`
        );
      }
    });

    it('all policies should include SSL cert paths', () => {
      const policies = [
        npmPolicy, pypiPolicy, mavenPolicy, cargoPolicy,
        rubygemsPolicy, composerPolicy, denoPolicy, gomodPolicy, bunPolicy,
      ];
      for (const policyFn of policies) {
        const policy = policyFn();
        strict.ok(
          policy.readPaths.some((p) => p.includes('ssl') || p.includes('cert')),
          `${policyFn.name} should include SSL cert paths`
        );
      }
    });
  });
});
