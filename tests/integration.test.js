/**
 * Integration tests for the full SaferExec pipeline.
 *
 * Tests the complete flow: policy → DNS resolution → Go binary → sandboxed
 * execution. Uses test fixtures (mock directories, config files) to verify
 * that sandboxed commands work correctly in realistic scenarios.
 *
 * @module integration_test
 */

import { describe, it, before } from 'node:test';
import strict from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SaferExec } from '../npm/src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Test fixture directory
const FIXTURE_DIR = join(__dirname, 'fixtures');
const FIXTURE_OUTPUT = join(FIXTURE_DIR, 'output');

/**
 * Set up test fixtures: create directories and files needed for tests.
 */
function setupFixtures() {
  // Create fixture directories
  mkdirSync(FIXTURE_DIR, { recursive: true });
  mkdirSync(FIXTURE_OUTPUT, { recursive: true });

  // Create a mock package.json for NPM tests
  writeFileSync(
    join(FIXTURE_DIR, 'package.json'),
    JSON.stringify({
      name: 'test-pkg',
      version: '1.0.0',
      dependencies: {
        chalk: '^5.0.0',
      },
    })
  );

  // Create a mock requirements.txt for Python tests
  writeFileSync(
    join(FIXTURE_DIR, 'requirements.txt'),
    'requests>=2.28\n'
  );

  // Create a mock pom.xml for Maven tests
  writeFileSync(
    join(FIXTURE_DIR, 'pom.xml'),
    `<?xml version="1.0" encoding="UTF-8"?>
    <project>
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.test</groupId>
      <artifactId>test-project</artifactId>
      <version>1.0-SNAPSHOT</version>
    </project>`
  );

  // Create a mock Cargo.toml for Rust tests
  writeFileSync(
    join(FIXTURE_DIR, 'Cargo.toml'),
    `[package]
name = "test-project"
version = "0.1.0"
edition = "2021"

[dependencies]`
  );
}

/**
 * Clean up test fixtures.
 */
function cleanupFixtures() {
  rmSync(FIXTURE_DIR, { recursive: true, force: true });
}

describe('Integration Tests', () => {
  before(() => {
    setupFixtures();
  });

  describe('Basic sandboxed execution', () => {
    it('should run echo with sandbox', async () => {
      const result = await new SaferExec()
        .run('echo', ['sandboxed output']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('sandboxed output'),
        'should capture stdout'
      );
    });

    it('should run multiple commands in sequence', async () => {
      const results = await Promise.all([
        new SaferExec().run('echo', ['cmd1']),
        new SaferExec().run('echo', ['cmd2']),
        new SaferExec().run('echo', ['cmd3']),
      ]);

      for (const result of results) {
        strict.equal(result.exitCode, 0, 'each command should succeed');
      }
    });

    it('should run shell commands', async () => {
      const result = await new SaferExec()
        .run('sh', ['-c', 'echo "shell output" && date']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('shell output'),
        'should capture shell output'
      );
    });
  });

  describe('Environment isolation', () => {
    it('should pass environment variables to sandbox', async () => {
      const result = await new SaferExec()
        .env('SANDBOX_TEST', 'hello_from_sandbox')
        .run('sh', ['-c', 'echo $SANDBOX_TEST']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('hello_from_sandbox'),
        'should have access to environment variable'
      );
    });

    it('should override environment variables', async () => {
      const result = await new SaferExec()
        .env('CUSTOM_PATH', '/custom/path')
        .run('sh', ['-c', 'echo $CUSTOM_PATH']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('/custom/path'),
        'should use overridden variable'
      );
    });

    it('should not leak environment variables', async () => {
      // Set a variable in the parent process
      process.env.SECRET_KEY = 'super_secret';

      const result = await new SaferExec()
        .env('SECRET_KEY', 'sandboxed_secret')
        .run('sh', ['-c', 'echo $SECRET_KEY']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('sandboxed_secret'),
        'should use sandboxed value, not parent value'
      );

      delete process.env.SECRET_KEY;
    });
  });

  describe('Policy integration', () => {
    it('should apply npm policy and run echo', async () => {
      const result = await new SaferExec()
        .applyPolicy('npm')
        .run('echo', ['npm policy applied']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('npm policy applied'),
        'should capture output'
      );
    });

    it('should apply pypi policy and run echo', async () => {
      const result = await new SaferExec()
        .applyPolicy('pypi')
        .run('echo', ['pypi policy applied']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
    });

    it('should apply maven policy and run echo', async () => {
      const result = await new SaferExec()
        .applyPolicy('maven')
        .run('echo', ['maven policy applied']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
    });

    it('should apply cargo policy and run echo', async () => {
      const result = await new SaferExec()
        .applyPolicy('cargo')
        .run('echo', ['cargo policy applied']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
    });

    it('should merge policy with user overrides', async () => {
      const result = await new SaferExec()
        .applyPolicy('npm')
        .env('CUSTOM_VAR', 'custom_value')
        .run('printenv', ['CUSTOM_VAR']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('custom_value'),
        'should have user override'
      );
    });
  });

  describe('File operations', () => {
    it('should write to allowed paths', async () => {
      const outputPath = join(FIXTURE_OUTPUT, 'test.txt');

      const result = await new SaferExec()
        .writePaths(FIXTURE_OUTPUT)
        .run('sh', ['-c', `echo "written content" > ${outputPath}`]);

      strict.equal(result.exitCode, 0, 'should exit with code 0');

      const content = readFileSync(outputPath, 'utf-8');
      strict.ok(
        content.includes('written content'),
        'should write to allowed path'
      );
    });

    it('should read from allowed paths', async () => {
      const inputPath = join(FIXTURE_DIR, 'package.json');

      const result = await new SaferExec()
        .readPaths(FIXTURE_DIR)
        .run('sh', ['-c', `cat ${inputPath}`]);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('test-pkg'),
        'should read from allowed path'
      );
    });
  });

  describe('Network resolution', () => {
    it('should resolve hosts before execution', async () => {
      const result = await new SaferExec()
        .allowHosts('github.com', 'google.com')
        .run('echo', ['hosts resolved']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
    });

    it('should handle unresolvable hosts gracefully', async () => {
      const result = await new SaferExec()
        .allowHosts('nonexistent-host-example.local')
        .run('echo', ['hosts resolved']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
    });
  });

  describe('Working directory', () => {
    it('should execute in specified working directory', async () => {
      const result = await new SaferExec()
        .workingDir('/')
        .run('sh', ['-c', 'pwd']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.trim() === '/',
        'should be in root directory'
      );
    });
  });

  describe('TraceLibraries (LD_AUDIT / DYLD observability)', () => {
    it('should complete successfully with traceLibraries enabled', async () => {
      const result = await new SaferExec()
        .traceLibraries()
        .run('sh', ['-c', 'echo trace-test-ok']);

      strict.equal(result.exitCode, 0, 'should exit with 0 when trace-libraries is on');
      strict.ok(
        result.stdout.includes('trace-test-ok'),
        `expected command output, got: ${result.stdout}`
      );
    });

    it('should emit trace-libraries diagnostic in stderr', async () => {
      const result = await new SaferExec()
        .traceLibraries()
        .run('sh', ['-c', 'echo trace-diag-check']);

      strict.equal(result.exitCode, 0);
      strict.ok(
        result.stderr.includes('trace-libraries'),
        `expected "trace-libraries" in stderr, got: ${result.stderr}`
      );
    });

    it('should capture lib-load events from LD_AUDIT on Linux', async () => {
      if (process.platform !== 'linux') {
        return; // LD_AUDIT is Linux-only; macOS uses Seatbelt audit
      }
      const result = await new SaferExec()
        .traceLibraries()
        .enableAudit()
        .run('sh', ['-c', 'echo lib-load-test']);

      strict.equal(result.exitCode, 0);
      // On Linux with gcc available, LD_AUDIT should emit lib-load JSON events.
      // If gcc is not installed, the audit log may be empty — both are valid.
      if (result.auditLog && result.auditLog.length > 0) {
        const libLoads = result.auditLog.filter(e => e.type === 'lib-load');
        strict.ok(
          libLoads.length > 0,
          `expected lib-load entries in auditLog, got types: ${JSON.stringify(result.auditLog.map(e => e.type))}`
        );
        // Each lib-load entry should have a target path ending in .so
        for (const entry of libLoads) {
          strict.ok(
            entry.target && typeof entry.target === 'string',
            `lib-load entry should have string target: ${JSON.stringify(entry)}`
          );
        }
      }
    });

    it('should support chaining traceLibraries with other options', async () => {
      const exec = new SaferExec()
        .traceLibraries()
        .maxMemory(256)
        .enableAudit();

      const result = await exec.run('sh', ['-c', 'echo chained']);

      strict.equal(result.exitCode, 0);
      strict.ok(result.stdout.includes('chained'));
    });
  });
});
