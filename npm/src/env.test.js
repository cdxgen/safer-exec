/**
 * Unit tests for environment variable hardening (loader-control stripping).
 *
 * @module env_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { isDangerousEnv, stripDangerousEnv } from './env.js';
import { SaferExec } from './index.js';

describe('env hardening', () => {
  describe('isDangerousEnv()', () => {
    it('flags loader-control variables', () => {
      for (const k of [
        'DYLD_INSERT_LIBRARIES',
        'DYLD_LIBRARY_PATH',
        'LD_PRELOAD',
        'LD_AUDIT',
        'DEVELOPER_DIR',
        'NODE_OPTIONS',
        'BASH_ENV',
        'PYTHONPATH',
        'GCONV_PATH',
      ]) {
        strict.equal(isDangerousEnv(k), true, `${k} should be dangerous`);
        strict.equal(isDangerousEnv(k.toLowerCase()), true, `${k} lowercase should be dangerous`);
      }
    });

    it('treats ordinary variables as safe', () => {
      for (const k of ['PATH', 'HOME', 'NODE_ENV', 'npm_config_loglevel', 'TMPDIR', 'LANG']) {
        strict.equal(isDangerousEnv(k), false, `${k} should be safe`);
      }
    });
  });

  describe('stripDangerousEnv()', () => {
    it('drops loader-control vars by default', () => {
      const out = stripDangerousEnv({
        PATH: '/usr/bin',
        DYLD_INSERT_LIBRARIES: '/tmp/evil.dylib',
        LD_PRELOAD: '/tmp/evil.so',
        NODE_OPTIONS: '--require /tmp/x.js',
        NODE_ENV: 'production',
      });
      strict.equal(out.PATH, '/usr/bin');
      strict.equal(out.NODE_ENV, 'production');
      strict.ok(!('DYLD_INSERT_LIBRARIES' in out));
      strict.ok(!('LD_PRELOAD' in out));
      strict.ok(!('NODE_OPTIONS' in out));
    });

    it('re-admits a loader-control var named in the allow list', () => {
      const out = stripDangerousEnv(
        { DYLD_INSERT_LIBRARIES: '/opt/x.dylib', LD_PRELOAD: '/tmp/y.so' },
        ['DYLD_INSERT_LIBRARIES'],
      );
      strict.equal(out.DYLD_INSERT_LIBRARIES, '/opt/x.dylib');
      strict.ok(!('LD_PRELOAD' in out));
    });
  });

  describe('SaferExec env integration', () => {
    it('does not pass loader-control vars to the config env', async () => {
      const exec = new SaferExec()
        .env('DYLD_INSERT_LIBRARIES', '/tmp/evil.dylib')
        .env('NODE_ENV', 'production');
      const { config } = await exec._buildConfig('node', ['-v']);
      strict.ok(!('DYLD_INSERT_LIBRARIES' in config.env));
      strict.equal(config.env.NODE_ENV, 'production');
    });

    it('allowEnvs re-admits a named loader-control var', async () => {
      const exec = new SaferExec()
        .env('DYLD_INSERT_LIBRARIES', '/opt/instrument.dylib')
        .allowEnvs('DYLD_INSERT_LIBRARIES');
      const { config } = await exec._buildConfig('node', ['-v']);
      strict.equal(config.env.DYLD_INSERT_LIBRARIES, '/opt/instrument.dylib');
    });
  });
});
