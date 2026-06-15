/**
 * Unit tests for built-in policy modules.
 *
 * @module policies_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { npmPolicy } from './policies/npm.js';
import { yarnPolicy } from './policies/yarn.js';
import { pnpmPolicy } from './policies/pnpm.js';
import { pnpmInstallPolicy } from './policies/pnpmInstall.js';
import { pypiPolicy } from './policies/pypi.js';
import { uvPolicy } from './policies/uv.js';
import { mavenPolicy } from './policies/maven.js';
import { cargoPolicy } from './policies/cargo.js';
import { rubygemsPolicy } from './policies/rubygems.js';
import { composerPolicy } from './policies/composer.js';
import { denoPolicy } from './policies/deno.js';
import { gomodPolicy } from './policies/gomod.js';
import { bunPolicy } from './policies/bun.js';
import { pokuPolicy } from './policies/poku.js';
import { cdxgenPolicy } from './policies/cdxgen.js';
import { getSslPaths } from './policies/sslhelper.js';

const home = process.env.HOME || process.env.USERPROFILE || '';

function hasBroadSystemPath(paths) {
  const broad = ['/usr', '/opt', '/etc'];
  return paths.some((p) => broad.includes(p));
}

function hasHomeWildcard(paths) {
  return paths.some((p) => p === home || p === '/home' || p === '/Users');
}

function hasGlobalTmp(paths) {
  const tmp = tmpdir();
  return paths.some((p) => p === tmp);
}

describe('policies', () => {
  describe('npmPolicy', () => {
    const policy = npmPolicy();

    it('should have non-empty allowHosts', () => {
      strict.ok(policy.allowHosts.length > 0);
    });

    it('should include Node binary dir', () => {
      const nodeDir = dirname(process.execPath);
      strict.ok(policy.readPaths.some((p) => p === nodeDir), 'should include getNodeDir()');
    });

    it('should not include entire system dirs', () => {
      strict.equal(hasBroadSystemPath(policy.readPaths), false);
      strict.equal(hasBroadSystemPath(policy.writePaths), false);
    });

    it('should not include entire home directory', () => {
      strict.equal(hasHomeWildcard(policy.readPaths), false);
      strict.equal(hasHomeWildcard(policy.writePaths), false);
    });

    it('should not include global temp', () => {
      strict.equal(hasGlobalTmp(policy.readPaths), false);
      strict.equal(hasGlobalTmp(policy.writePaths), false);
    });

    it('should include SSL paths', () => {
      strict.ok(policy.readPaths.some((p) => p.includes('ssl') || p.includes('cert')));
    });

    it('should include project config files', () => {
      const hasPkgJson = policy.readPaths.some((p) => p.endsWith('package.json'));
      strict.ok(hasPkgJson);
    });

    it('should block fork and exec', () => {
      strict.equal(policy.blockFork, true);
      strict.ok(policy.blockExec.length > 0);
    });
  });

  describe('yarnPolicy', () => {
    const policy = yarnPolicy();

    it('should not include broad system dirs', () => {
      strict.equal(hasBroadSystemPath(policy.readPaths), false);
      strict.equal(hasBroadSystemPath(policy.writePaths), false);
    });

    it('should not include global temp', () => {
      strict.equal(hasGlobalTmp(policy.readPaths), false);
      strict.equal(hasGlobalTmp(policy.writePaths), false);
    });

    it('should include yarn.lock', () => {
      strict.ok(policy.readPaths.some((p) => p.endsWith('yarn.lock')));
    });
  });

  describe('pnpmPolicy', () => {
    const policy = pnpmPolicy();

    it('should not include broad system dirs', () => {
      strict.equal(hasBroadSystemPath(policy.readPaths), false);
      strict.equal(hasBroadSystemPath(policy.writePaths), false);
    });

    it('should not include cwd wildcard', () => {
      const cwd = process.cwd();
      strict.equal(policy.readPaths.includes(cwd), false, 'should not include bare cwd');
    });

    it('should not include global temp', () => {
      strict.equal(hasGlobalTmp(policy.readPaths), false);
    });

    it('should include pnpm-specific config paths', () => {
      const hasPnpmConfig = policy.readPaths.some((p) => p.includes('.config/pnpm'));
      strict.ok(hasPnpmConfig);
    });

    it('should enable resolveSymlinks', () => {
      strict.equal(policy.resolveSymlinks, true);
    });
  });

  describe('pnpmInstallPolicy', () => {
    const policy = pnpmInstallPolicy();

    it('should not include /usr, /opt, /etc', () => {
      strict.equal(hasBroadSystemPath(policy.readPaths), false);
    });

    it('should allow execution', () => {
      strict.equal(policy.blockFork, false);
      strict.deepEqual(policy.blockExec, []);
    });
  });

  describe('yarnPolicy', () => {
    const policy = yarnPolicy();

    it('should include yarn-specific paths', () => {
      strict.ok(policy.writePaths.some((p) => p.includes('.yarn')));
    });
  });

  describe('pypiPolicy', () => {
    const policy = pypiPolicy();

    it('should have non-empty allowHosts', () => {
      strict.ok(policy.allowHosts.length > 0);
    });

    it('should include pyproject.toml and requirements.txt', () => {
      strict.ok(policy.readPaths.some((p) => p.endsWith('pyproject.toml')));
      strict.ok(policy.readPaths.some((p) => p.endsWith('requirements.txt')));
    });

    it('should include venv and cache paths', () => {
      strict.ok(policy.writePaths.some((p) => p.includes('.venv')));
      strict.ok(policy.writePaths.some((p) => p.includes('pip')));
    });
  });

  describe('uvPolicy', () => {
    const policy = uvPolicy();

    it('should have non-empty allowHosts', () => {
      strict.ok(policy.allowHosts.length > 0);
    });

    it('should include pyproject.toml and uv.lock', () => {
      strict.ok(policy.readPaths.some((p) => p.endsWith('pyproject.toml')), 'should have pyproject.toml');
      strict.ok(policy.readPaths.some((p) => p.endsWith('uv.lock')), 'should have uv.lock');
    });

    it('should include uv cache directory', () => {
      strict.ok(policy.writePaths.some((p) => p.includes('/uv')), 'should have uv cache');
    });

    it('should not include broad system dirs', () => {
      strict.equal(hasBroadSystemPath(policy.readPaths), false);
      strict.equal(hasBroadSystemPath(policy.writePaths), false);
    });

    it('should not include global temp', () => {
      strict.equal(hasGlobalTmp(policy.readPaths), false);
    });
  });

  describe('mavenPolicy', () => {
    const policy = mavenPolicy();

    it('should have non-empty allowHosts', () => {
      strict.ok(policy.allowHosts.length > 0);
    });

    it('should include pom.xml and build.gradle', () => {
      strict.ok(policy.readPaths.some((p) => p.endsWith('pom.xml')));
      strict.ok(policy.readPaths.some((p) => p.endsWith('build.gradle')));
    });

    it('should include maven/gradle cache', () => {
      strict.ok(policy.writePaths.some((p) => p.includes('.m2') || p.includes('.gradle')));
    });
  });

  describe('cargoPolicy', () => {
    const policy = cargoPolicy();

    it('should have non-empty allowHosts', () => {
      strict.ok(policy.allowHosts.length > 0);
    });

    it('should not include entire rustupHome/cargoHome', () => {
      const hasEntire = policy.readPaths.some((p) => p === join(home, '.rustup') || p === join(home, '.cargo'));
      strict.equal(hasEntire, false, 'should not include entire .rustup or .cargo');
    });

    it('should include toolchains and registry subdirs', () => {
      strict.ok(policy.readPaths.some((p) => p.includes('toolchains')));
      strict.ok(policy.readPaths.some((p) => p.includes('registry')));
    });
  });

  describe('rubygemsPolicy', () => {
    const policy = rubygemsPolicy();

    it('should not include entire version manager dirs', () => {
      const rbenv = join(home, '.rbenv');
      const rvm = join(home, '.rvm');
      const asdf = join(home, '.asdf');
      const hasEntireVM = policy.readPaths.some((p) => p === rbenv || p === rvm || p === asdf);
      strict.equal(hasEntireVM, false, 'should not include entire .rbenv, .rvm, or .asdf');
    });

    it('should not include global temp', () => {
      strict.equal(hasGlobalTmp(policy.readPaths), false);
      strict.equal(hasGlobalTmp(policy.writePaths), false);
    });
  });

  describe('gomodPolicy', () => {
    const policy = gomodPolicy();

    it('should include go.mod and go.sum', () => {
      strict.ok(policy.readPaths.some((p) => p.endsWith('go.mod')));
      strict.ok(policy.readPaths.some((p) => p.endsWith('go.sum')));
    });

    it('should not include entire goPath as write', () => {
      const goPath = process.env.GOPATH || join(home, 'go');
      const hasEntireGoPathWrite = policy.writePaths.some((p) => p === goPath);
      strict.equal(hasEntireGoPathWrite, false, 'should not include entire goPath for write');
    });

    it('should include pkg/mod for write', () => {
      strict.ok(policy.writePaths.some((p) => p.includes('pkg/mod')));
    });
  });

  describe('denoPolicy', () => {
    const policy = denoPolicy();

    it('should not include entire system lib dir', () => {
      const hasSystemLib = policy.readPaths.some((p) => p === '/usr/lib' || p === '/usr/local/lib');
      strict.equal(hasSystemLib, false, 'should not include /usr/lib or /usr/local/lib');
    });

    it('should include deno cache', () => {
      strict.ok(policy.writePaths.some((p) => p.includes('deno')));
    });
  });

  describe('bunPolicy', () => {
    const policy = bunPolicy();

    it('should not include entire system lib dir', () => {
      const hasSystemLib = policy.readPaths.some((p) => p === '/usr/lib' || p === '/usr/local/lib');
      strict.equal(hasSystemLib, false, 'should not include /usr/lib or /usr/local/lib');
    });

    it('should include bun install dir', () => {
      strict.ok(policy.writePaths.some((p) => p.includes('.bun')), 'should include .bun dir');
    });
  });

  describe('pokuPolicy', () => {
    const policy = pokuPolicy();

    it('should allow loopback and execution', () => {
      strict.equal(policy.allowLoopback, true);
      strict.equal(policy.blockFork, false);
      strict.deepEqual(policy.blockExec, []);
    });

    it('should not include cwd wildcard in read', () => {
      const cwd = process.cwd();
      strict.equal(policy.readPaths.includes(cwd), false, 'should not include bare cwd');
    });

    it('should not include global temp', () => {
      strict.equal(hasGlobalTmp(policy.readPaths), false);
      strict.equal(hasGlobalTmp(policy.writePaths), false);
    });
  });

  describe('cdxgenPolicy', () => {
    const policy = cdxgenPolicy();

    it('should not include /usr, /opt, /etc', () => {
      strict.equal(hasBroadSystemPath(policy.readPaths), false);
    });

    it('should not include entire .cache', () => {
      const hasEntireCache = policy.writePaths.some((p) => p === join(home, '.cache'));
      strict.equal(hasEntireCache, false, 'should not include entire .cache');
    });

    it('should allow hosts and execution', () => {
      strict.ok(policy.allowHosts.length > 0);
      strict.equal(policy.allowLoopback, true);
      strict.equal(policy.blockFork, false);
      strict.deepEqual(policy.blockExec, []);
    });
  });

  describe('sslhelper', () => {
    const paths = getSslPaths();

    it('should return ssl cert paths', () => {
      strict.ok(paths.length > 0);
      strict.ok(paths.some((p) => p.includes('ssl') || p.includes('cert') || p.includes('ca-certificates') || p.includes('openssl')));
    });

    it('should not contain empty paths', () => {
      for (const p of paths) {
        strict.ok(p.length > 0, `path should not be empty: "${p}"`);
      }
    });
  });

  describe('all policies', () => {
    const all = {
      npm: npmPolicy,
      yarn: yarnPolicy,
      pnpm: pnpmPolicy,
      pnpmInstall: pnpmInstallPolicy,
      pypi: pypiPolicy,
      uv: uvPolicy,
      maven: mavenPolicy,
      cargo: cargoPolicy,
      rubygems: rubygemsPolicy,
      composer: composerPolicy,
      deno: denoPolicy,
      gomod: gomodPolicy,
      bun: bunPolicy,
      poku: pokuPolicy,
      cdxgen: cdxgenPolicy,
    };

    for (const [name, fn] of Object.entries(all)) {
      it(`${name} should return an object with expected shape`, () => {
        const p = fn();
        strict.ok(Array.isArray(p.readPaths), `${name}: readPaths should be array`);
        strict.ok(Array.isArray(p.writePaths), `${name}: writePaths should be array`);
        strict.ok(Array.isArray(p.allowHosts), `${name}: allowHosts should be array`);
        strict.equal(typeof p.blockFork, 'boolean', `${name}: blockFork should be boolean`);
        strict.ok(Array.isArray(p.blockExec), `${name}: blockExec should be array`);
      });

      it(`${name} should not include broad system dirs /usr, /opt, /etc`, () => {
        const p = fn();
        strict.equal(hasBroadSystemPath(p.readPaths), false, `${name}: readPaths contains broad system dir`);
        strict.equal(hasBroadSystemPath(p.writePaths), false, `${name}: writePaths contains broad system dir`);
      });

      it(`${name} should not write to global temp`, () => {
        const p = fn();
        strict.equal(hasGlobalTmp(p.writePaths), false, `${name}: writePaths contains global temp`);
      });
    }
  });

  describe('hardening flags', () => {
    // Every hardened policy denies writes to persistence locations.
    const persistencePolicies = {
      npm: npmPolicy, yarn: yarnPolicy, pnpm: pnpmPolicy, bun: bunPolicy,
      deno: denoPolicy, pypi: pypiPolicy, uv: uvPolicy, maven: mavenPolicy,
      cargo: cargoPolicy, rubygems: rubygemsPolicy, composer: composerPolicy,
      gomod: gomodPolicy, cdxgen: cdxgenPolicy,
    };
    for (const [name, fn] of Object.entries(persistencePolicies)) {
      it(`${name} denies persistence writes`, () => {
        strict.equal(fn().denyPersistenceWrites, true);
      });
    }

    // Non-interpreter ecosystems block the entitled scripting engines.
    for (const [name, fn] of Object.entries({
      npm: npmPolicy, yarn: yarnPolicy, pnpm: pnpmPolicy, bun: bunPolicy,
      deno: denoPolicy, maven: mavenPolicy, cargo: cargoPolicy,
      composer: composerPolicy, gomod: gomodPolicy,
    })) {
      it(`${name} blocks interpreters`, () => {
        strict.equal(fn().blockInterpreters, true);
      });
    }

    // Interpreter-driven ecosystems must NOT block interpreters (it would
    // break their own runtime child processes).
    for (const [name, fn] of Object.entries({ pypi: pypiPolicy, uv: uvPolicy, rubygems: rubygemsPolicy })) {
      it(`${name} does not block interpreters`, () => {
        strict.ok(!fn().blockInterpreters);
      });
    }
  });
});
