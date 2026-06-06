/**
 * Tests for filesystem mutation diffing (enableDiff).
 *
 * Verifies that the engine correctly tracks filesystem changes during
 * execution and returns an accurate diff report with added, modified,
 * and deleted files.
 *
 * @module fsdiff_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec } from './index.js';
import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, realpathSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Create a temporary test directory with known files.
 * @returns {string} Path to the test directory
 */
function createTestDir() {
  // On macOS, /tmp is a symlink to /private/tmp — resolve it so the
  // Seatbelt subpath rule matches without symlink confusion.
  const realTmp = realpathSync(tmpdir());
  const dir = join(realTmp, `safer-fsdiff-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });

  // Create initial files
  writeFileSync(join(dir, 'file_a.txt'), 'original content A');
  writeFileSync(join(dir, 'file_b.txt'), 'original content B');
  mkdirSync(join(dir, 'subdir'), { recursive: true });
  writeFileSync(join(dir, 'subdir', 'nested.txt'), 'nested content');

  return dir;
}

/**
 * Clean up a test directory.
 * @param {string} dir
 */
function cleanupTestDir(dir) {
  if (existsSync(dir)) {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('Filesystem Diffing (enableDiff)', () => {
  let testDir;

  describe('Added files', () => {
    it('should detect newly created files', async () => {
      testDir = createTestDir();
      const newFile = join(testDir, 'new_file.txt');

      try {
        const result = await new SaferExec()
          .writePaths(testDir)
          .enableDiff()
          .run('sh', ['-c', `echo "new content" > ${newFile}`]);

        strict.equal(result.exitCode, 0, 'command should succeed');
        strict.ok(result.fsDiff, 'should have fsDiff in result');
        strict.ok(result.fsDiff.added, 'fsDiff should have added array');

        // The new file should be in the added list
        const addedPaths = result.fsDiff.added.map((e) => e.path);
        strict.ok(
          addedPaths.some((p) => p.includes('new_file.txt')),
          `new_file.txt should be in added list. Added: ${JSON.stringify(addedPaths)}`
        );
      } finally {
        cleanupTestDir(testDir);
      }
    });

    it('should detect newly created directories', async () => {
      testDir = createTestDir();
      const newDir = join(testDir, 'new_dir');

      try {
        const result = await new SaferExec()
          .writePaths(testDir)
          .enableDiff()
          .run('mkdir', [newDir]);

        strict.equal(result.exitCode, 0, 'command should succeed');
        strict.ok(result.fsDiff, 'should have fsDiff in result');

        const addedPaths = result.fsDiff.added.map((e) => e.path);
        strict.ok(
          addedPaths.some((p) => p.includes('new_dir')),
          `new_dir should be in added list. Added: ${JSON.stringify(addedPaths)}`
        );
      } finally {
        cleanupTestDir(testDir);
      }
    });

    it('should detect multiple added files', async () => {
      testDir = createTestDir();

      try {
        const result = await new SaferExec()
          .writePaths(testDir)
          .enableDiff()
          .run('sh', ['-c', `
            echo "one" > ${join(testDir, 'one.txt')}
            echo "two" > ${join(testDir, 'two.txt')}
            echo "three" > ${join(testDir, 'three.txt')}
          `]);

        strict.equal(result.exitCode, 0, 'command should succeed');
        strict.ok(result.fsDiff, 'should have fsDiff in result');

        const addedPaths = result.fsDiff.added.map((e) => e.path);
        strict.ok(
          addedPaths.some((p) => p.includes('one.txt')),
          'one.txt should be in added list'
        );
        strict.ok(
          addedPaths.some((p) => p.includes('two.txt')),
          'two.txt should be in added list'
        );
        strict.ok(
          addedPaths.some((p) => p.includes('three.txt')),
          'three.txt should be in added list'
        );
      } finally {
        cleanupTestDir(testDir);
      }
    });
  });

  describe('Modified files', () => {
    it('should detect modified files', async () => {
      testDir = createTestDir();

      try {
        const result = await new SaferExec()
          .writePaths(testDir)
          .enableDiff()
          .run('sh', ['-c', `echo "modified content" > ${join(testDir, 'file_a.txt')}`]);

        strict.equal(result.exitCode, 0, 'command should succeed');
        strict.ok(result.fsDiff, 'should have fsDiff in result');

        const modifiedPaths = result.fsDiff.modified.map((e) => e.path);
        strict.ok(
          modifiedPaths.some((p) => p.includes('file_a.txt')),
          `file_a.txt should be in modified list. Modified: ${JSON.stringify(modifiedPaths)}`
        );
      } finally {
        cleanupTestDir(testDir);
      }
    });

    it('should detect modified files with size change', async () => {
      testDir = createTestDir();

      try {
        // Write a significantly different size
        const result = await new SaferExec()
          .writePaths(testDir)
          .enableDiff()
          .run('sh', ['-c', `printf '%0*s' 1024 '' > ${join(testDir, 'file_b.txt')}`]);

        strict.equal(result.exitCode, 0, 'command should succeed');
        strict.ok(result.fsDiff, 'should have fsDiff in result');

        const modifiedPaths = result.fsDiff.modified.map((e) => e.path);
        strict.ok(
          modifiedPaths.some((p) => p.includes('file_b.txt')),
          'file_b.txt should be in modified list'
        );
      } finally {
        cleanupTestDir(testDir);
      }
    });
  });

  describe('Deleted files', () => {
    it('should detect deleted files', async () => {
      testDir = createTestDir();

      try {
        const result = await new SaferExec()
          .writePaths(testDir)
          .enableDiff()
          .run('rm', [join(testDir, 'file_a.txt')]);

        strict.equal(result.exitCode, 0, 'command should succeed');
        strict.ok(result.fsDiff, 'should have fsDiff in result');

        const deletedPaths = result.fsDiff.deleted.map((e) => e.path);
        strict.ok(
          deletedPaths.some((p) => p.includes('file_a.txt')),
          `file_a.txt should be in deleted list. Deleted: ${JSON.stringify(deletedPaths)}`
        );
      } finally {
        cleanupTestDir(testDir);
      }
    });
  });

  describe('Mixed changes', () => {
    it('should detect added, modified, and deleted files simultaneously', async () => {
      testDir = createTestDir();

      try {
        const result = await new SaferExec()
          .writePaths(testDir)
          .enableDiff()
          .run('sh', ['-c', `
            echo "new" > ${join(testDir, 'added.txt')}
            echo "modified" > ${join(testDir, 'file_a.txt')}
            rm ${join(testDir, 'file_b.txt')}
          `]);

        strict.equal(result.exitCode, 0, 'command should succeed');
        strict.ok(result.fsDiff, 'should have fsDiff in result');

        const addedPaths = result.fsDiff.added.map((e) => e.path);
        const modifiedPaths = result.fsDiff.modified.map((e) => e.path);
        const deletedPaths = result.fsDiff.deleted.map((e) => e.path);

        strict.ok(
          addedPaths.some((p) => p.includes('added.txt')),
          'added.txt should be in added list'
        );
        strict.ok(
          modifiedPaths.some((p) => p.includes('file_a.txt')),
          'file_a.txt should be in modified list'
        );
        strict.ok(
          deletedPaths.some((p) => p.includes('file_b.txt')),
          'file_b.txt should be in deleted list'
        );
      } finally {
        cleanupTestDir(testDir);
      }
    });
  });

  describe('No changes', () => {
    it('should return empty diff when no changes made', async () => {
      testDir = createTestDir();

      try {
        const result = await new SaferExec()
          .writePaths(testDir)
          .enableDiff()
          .run('echo', ['no changes']);

        strict.equal(result.exitCode, 0, 'command should succeed');
        strict.ok(result.fsDiff, 'should have fsDiff in result');

        // Should have no changes (or only minimal metadata changes)
        const addedCount = result.fsDiff.added?.length ?? 0;
        const modifiedCount = result.fsDiff.modified?.length ?? 0;
        const deletedCount = result.fsDiff.deleted?.length ?? 0;
        strict.ok(
          addedCount === 0 && modifiedCount === 0 && deletedCount === 0,
          `should have no changes, got: +${addedCount} ~${modifiedCount} -${deletedCount}`
        );
      } finally {
        cleanupTestDir(testDir);
      }
    });
  });

  describe('Diff entry properties', () => {
    it('should include file size in diff entries', async () => {
      testDir = createTestDir();

      try {
        const result = await new SaferExec()
          .writePaths(testDir)
          .enableDiff()
          .run('sh', ['-c', `echo "sized content" > ${join(testDir, 'sized.txt')}`]);

        strict.equal(result.exitCode, 0, 'command should succeed');
        strict.ok(result.fsDiff, 'should have fsDiff in result');

        const sizedEntry = result.fsDiff.added.find((e) => e.path.includes('sized.txt'));
        strict.ok(sizedEntry, 'should find sized.txt in added entries');
        strict.ok(sizedEntry.size > 0, 'file size should be > 0');
      } finally {
        cleanupTestDir(testDir);
      }
    });

    it('should mark directories correctly', async () => {
      testDir = createTestDir();

      try {
        const result = await new SaferExec()
          .writePaths(testDir)
          .enableDiff()
          .run('mkdir', [join(testDir, 'new_dir')]);

        strict.equal(result.exitCode, 0, 'command should succeed');
        strict.ok(result.fsDiff, 'should have fsDiff in result');

        const dirEntry = result.fsDiff.added.find((e) => e.path.includes('new_dir'));
        strict.ok(dirEntry, 'should find new_dir in added entries');
        strict.equal(dirEntry.isDir, true, 'directory should be marked as isDir');
      } finally {
        cleanupTestDir(testDir);
      }
    });
  });

  describe('Diff without enableDiff', () => {
    it('should not include fsDiff when enableDiff is not set', async () => {
      const result = await new SaferExec()
        .run('echo', ['hello']);

      strict.equal(result.exitCode, 0, 'command should succeed');
      strict.equal(result.fsDiff, undefined, 'should not have fsDiff');
    });
  });

  describe('Chaining with other methods', () => {
    it('should work with maxMemory', async () => {
      testDir = createTestDir();

      try {
        const result = await new SaferExec()
          .writePaths(testDir)
          .maxMemory(256)
          .enableDiff()
          .run('sh', ['-c', `echo "chained" > ${join(testDir, 'chained.txt')}`]);

        strict.equal(result.exitCode, 0, 'command should succeed');
        strict.ok(result.fsDiff, 'should have fsDiff');
      } finally {
        cleanupTestDir(testDir);
      }
    });

    it('should work with enableAudit', async () => {
      testDir = createTestDir();

      try {
        const result = await new SaferExec()
          .writePaths(testDir)
          .enableAudit()
          .enableDiff()
          .run('sh', ['-c', `echo "both" > ${join(testDir, 'both.txt')}`]);

        strict.equal(result.exitCode, 0, 'command should succeed');
        strict.ok(result.fsDiff, 'should have fsDiff');
      } finally {
        cleanupTestDir(testDir);
      }
    });
  });

  describe('Real-world scenario: npm-like install', () => {
    it('should track node_modules creation', async () => {
      testDir = createTestDir();
      const nodeModules = join(testDir, 'node_modules');
      const pkgDir = join(nodeModules, 'chalk');

      try {
        const result = await new SaferExec()
          .writePaths(testDir)
          .enableDiff()
          .run('sh', ['-c', `
            mkdir -p ${pkgDir}
            echo '{"name":"chalk","version":"5.0.0"}' > ${join(pkgDir, 'package.json')}
            echo '{"name":"test","dependencies":{"chalk":"5.0.0"}}' > ${join(testDir, 'package.json')}
          `]);

        strict.equal(result.exitCode, 0, 'command should succeed');
        strict.ok(result.fsDiff, 'should have fsDiff');

        const addedPaths = result.fsDiff.added.map((e) => e.path);
        strict.ok(
          addedPaths.some((p) => p.includes('node_modules') || p.includes('package.json')),
          'should detect node_modules or package.json changes'
        );
      } finally {
        cleanupTestDir(testDir);
      }
    });
  });
});
