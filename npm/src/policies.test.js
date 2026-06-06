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

  describe('policy defaults', () => {
    it('all policies should have non-empty allowHosts', () => {
      const policies = [npmPolicy, pypiPolicy, mavenPolicy, cargoPolicy, rubygemsPolicy, composerPolicy, denoPolicy, gomodPolicy, bunPolicy];
      for (const policyFn of policies) {
        strict.ok(policyFn().allowHosts.length > 0, `${policyFn.name} should have allowHosts`);
      }
    });
  });
});