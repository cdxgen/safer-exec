/**
 * Unit tests for the namespace/chroot hardening options exposed by SaferExec:
 * allowUserns and allowChrootFallback. These are secure-by-default (both false)
 * and must round-trip correctly into the ExecConfig handed to the Go engine.
 *
 * @module hardening_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec } from './index.js';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeFileSync, unlinkSync } from 'node:fs';

describe('allowUserns', () => {
  it('should default to false (nested namespaces blocked)', () => {
    strict.equal(new SaferExec()._allowUserns, false);
  });

  it('should be settable via constructor option', () => {
    strict.equal(new SaferExec({ allowUserns: true })._allowUserns, true);
  });

  it('should return this for chaining and toggle the flag', () => {
    const exec = new SaferExec();
    strict.equal(exec.allowUserns(), exec);
    strict.equal(exec._allowUserns, true);
    exec.allowUserns(false);
    strict.equal(exec._allowUserns, false);
  });

  it('should be false in _buildConfig output by default', async () => {
    const { config } = await new SaferExec()._buildConfig('echo', ['hi']);
    strict.equal(config.allowUserns, false);
  });

  it('should propagate true into _buildConfig output', async () => {
    const { config } = await new SaferExec({ allowUserns: true })._buildConfig('echo', ['hi']);
    strict.equal(config.allowUserns, true);
  });
});

describe('allowChrootFallback', () => {
  it('should default to false (pivot_root failure is fatal)', () => {
    strict.equal(new SaferExec()._allowChrootFallback, false);
  });

  it('should be settable via constructor option', () => {
    strict.equal(new SaferExec({ allowChrootFallback: true })._allowChrootFallback, true);
  });

  it('should return this for chaining and toggle the flag', () => {
    const exec = new SaferExec();
    strict.equal(exec.allowChrootFallback(), exec);
    strict.equal(exec._allowChrootFallback, true);
    exec.allowChrootFallback(false);
    strict.equal(exec._allowChrootFallback, false);
  });

  it('should propagate into _buildConfig output', async () => {
    const { config } = await new SaferExec({ allowChrootFallback: true })._buildConfig('echo', ['hi']);
    strict.equal(config.allowChrootFallback, true);
  });
});

describe('hardening options via applyPolicyFile', () => {
  it('should honor allowUserns and allowChrootFallback from a policy file', () => {
    const path = join(tmpdir(), `safer-exec-hardening-${process.pid}.json`);
    writeFileSync(path, JSON.stringify({ allowUserns: true, allowChrootFallback: true }));
    try {
      const exec = new SaferExec().applyPolicyFile(path);
      strict.equal(exec._allowUserns, true);
      strict.equal(exec._allowChrootFallback, true);
    } finally {
      unlinkSync(path);
    }
  });

  it('should leave hardening defaults untouched when the policy omits them', () => {
    const path = join(tmpdir(), `safer-exec-hardening-empty-${process.pid}.json`);
    writeFileSync(path, JSON.stringify({ readPaths: ['/tmp'] }));
    try {
      const exec = new SaferExec().applyPolicyFile(path);
      strict.equal(exec._allowUserns, false);
      strict.equal(exec._allowChrootFallback, false);
    } finally {
      unlinkSync(path);
    }
  });
});
