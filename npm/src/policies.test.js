/**
 * Unit tests for the policy modules.
 *
 * @module policies_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { dirname } from 'node:path';
import { npmPolicy } from './policies/npm.js';
import { pypiPolicy } from './policies/pypi.js';
import { mavenPolicy } from './policies/maven.js';
import { cargoPolicy } from './policies/cargo.js';
import { rubygemsPolicy } from './policies/rubygems.js';
import { composerPolicy } from './policies/composer.js';
import { denoPolicy } from './policies/deno.js';
import { gomodPolicy } from './policies/gomod.js';
import { bunPolicy } from './policies/bun.js';
import { pokuPolicy } from './policies/poku.js';
import { cdxgenPolicy } from './policies/cdxgen.js';

describe('policies', () => {
  describe('npmPolicy', () => {
    it('should include Node.js binary paths', () => {
      const policy = npmPolicy();
      const nodeDir = dirname(process.execPath);
      strict.ok(
        policy.readPaths.some((p) => p.includes('node') || p.includes(nodeDir) || process.execPath.includes(p)),
        'should include Node.js paths'
      );
    });

    it('should include SSL certificate paths', () => {
      const policy = npmPolicy();
      strict.ok(policy.readPaths.some(p => p.includes('ssl') || p.includes('cert')));
    });
  });

  describe('pokuPolicy', () => {
    it('should allow loopback but have blockFork false', () => {
      const policy = pokuPolicy();
      strict.equal(policy.allowLoopback, true);
      strict.equal(policy.blockFork, false);
      strict.deepEqual(policy.blockExec, []);
    });
  });

  describe('cdxgenPolicy', () => {
    it('should allow hosts, loopback, and blockFork false', () => {
      const policy = cdxgenPolicy();
      strict.ok(policy.allowHosts.length > 0);
      strict.equal(policy.allowLoopback, true);
      strict.equal(policy.blockFork, false);
      strict.deepEqual(policy.blockExec, []);
    });
  });

  describe('policy defaults', () => {
    it('all standard ecosystem policies should have non-empty allowHosts', () => {
      const policies = [npmPolicy, pypiPolicy, mavenPolicy, cargoPolicy, rubygemsPolicy, composerPolicy, denoPolicy, gomodPolicy, bunPolicy, cdxgenPolicy];
      for (const policyFn of policies) {
        strict.ok(policyFn().allowHosts.length > 0, `${policyFn.name} should have allowHosts`);
      }
    });
  });
});