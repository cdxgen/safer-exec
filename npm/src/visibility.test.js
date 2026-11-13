/**
 * Unit tests for the host filesystem visibility model (visibility.js) and
 * the SaferExec methods built on it.
 *
 * The platform models run against an in-memory filesystem, so every platform
 * is covered on every host.
 *
 * @module visibility_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { mkdtempSync, rmSync, symlinkSync, writeFileSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildFilesystemView, resolveVisiblePathInView } from './visibility.js';
import { SaferExec } from './index.js';

/**
 * Builds filesystem probes over a POSIX tree described as
 * `{ path: 'dir' | 'file' | '->target' }`. Parent directories are implied.
 */
function fakeFs(entries) {
  const kind = (p) => {
    if (p === '/') {
      return 'dir';
    }
    if (entries[p] !== undefined) {
      return entries[p];
    }
    return Object.keys(entries).some((k) => k.startsWith(p + '/')) ? 'dir' : undefined;
  };
  const realpath = (p, depth = 0) => {
    if (depth > 20) {
      throw new Error('ELOOP');
    }
    const parts = p.split('/').filter(Boolean);
    let cur = '';
    for (let i = 0; i < parts.length; i++) {
      cur += '/' + parts[i];
      const k = kind(cur);
      if (k === undefined) {
        throw new Error(`ENOENT ${cur}`);
      }
      if (k.startsWith('->')) {
        const rest = parts.slice(i + 1).join('/');
        return realpath(k.slice(2) + (rest ? '/' + rest : ''), depth + 1);
      }
    }
    return cur || '/';
  };
  return {
    realpath,
    lstat: (p) => {
      const k = kind(p);
      if (k === undefined) {
        throw new Error(`ENOENT ${p}`);
      }
      return { isSymbolicLink: () => k.startsWith('->') };
    },
    exists: (p) => {
      try {
        realpath(p);
        return true;
      } catch {
        return false;
      }
    },
  };
}

const linuxTree = {
  '/usr/lib/libc.so.6': 'file',
  '/usr/lib/os-release': 'file',
  '/lib': '->/usr/lib',
  '/etc/hosts': 'file',
  '/etc/shadow': 'file',
  '/etc/os-release': '->/usr/lib/os-release',
  '/home/u/.aws/credentials': 'file',
  '/home/u/notes.txt': 'file',
  '/srv/proj/libplugin.so': 'file',
  '/srv/proj/link': '->/home/u/.aws/credentials',
  '/srv/proj/sys-link': '->/usr/lib/libc.so.6',
  '/opt/tool': '->/secret',
  '/secret/key': 'file',
  '/tmp/scratch/a.so': 'file',
  '/var/tmp/b': 'file',
  '/dev/zero': 'file',
};

function linuxView(overrides = {}, tree = linuxTree) {
  const fs = fakeFs(tree);
  const view = buildFilesystemView({
    platform: 'linux',
    readPaths: ['/usr', '/lib', '/etc/hosts', '/etc/os-release', '/dev/zero', '/srv/proj'],
    writePaths: [],
    workingDir: '/srv/proj',
    cwd: '/srv/proj',
    home: '/home/u',
    ...overrides,
  }, fs);
  return { view, fs, visible: (p) => resolveVisiblePathInView(view, p, fs) };
}

describe('buildFilesystemView: linux', () => {
  it('rejects a link in the project that points at a hidden file', () => {
    const { visible } = linuxView();
    strict.equal(visible('/srv/proj/libplugin.so'), '/srv/proj/libplugin.so');
    strict.equal(visible('/srv/proj/link'), null);
    strict.equal(visible('/home/u/.aws/credentials'), null);
  });

  it('returns the resolved path of a link that stays inside the sandbox', () => {
    const { visible } = linuxView();
    strict.equal(visible('/srv/proj/sys-link'), '/usr/lib/libc.so.6');
    strict.equal(visible('/lib/libc.so.6'), '/usr/lib/libc.so.6');
    strict.equal(visible('/etc/os-release'), '/usr/lib/os-release');
  });

  it('rejects host files outside every read path', () => {
    const { visible } = linuxView();
    strict.equal(visible('/etc/hosts'), '/etc/hosts');
    strict.equal(visible('/etc/shadow'), null);
    strict.equal(visible('/home/u/notes.txt'), null);
  });

  it('skips a symlinked read path that resolves outside the allowed paths', () => {
    const { visible, view } = linuxView({ readPaths: ['/usr', '/opt/tool'] });
    strict.equal(visible('/opt/tool/key'), null);
    strict.equal(visible('/secret/key'), null);
    strict.ok(!view.readRoots.includes('/secret'));
  });

  it('rejects relative, missing and malformed paths', () => {
    const { visible } = linuxView();
    strict.equal(visible('srv/proj/libplugin.so'), null);
    strict.equal(visible('/srv/proj/missing.so'), null);
    strict.equal(visible('/srv/proj/libplugin.so\0'), null);
    strict.equal(visible(undefined), null);
  });

  it('hides /tmp and /var/tmp under privateTmp', () => {
    const plain = linuxView({ writePaths: ['/tmp/scratch', '/var/tmp'] });
    strict.equal(plain.visible('/tmp/scratch/a.so'), '/tmp/scratch/a.so');
    strict.equal(plain.visible('/var/tmp/b'), '/var/tmp/b');
    const priv = linuxView({ writePaths: ['/tmp/scratch', '/var/tmp'], privateTmp: true });
    strict.equal(priv.visible('/tmp/scratch/a.so'), null);
    strict.equal(priv.visible('/var/tmp/b'), null);
  });

  it('hides $HOME under protectHome tmpfs even when it is a read path', () => {
    const { visible } = linuxView({ readPaths: ['/usr', '/home/u'], protectHome: 'tmpfs' });
    strict.equal(visible('/home/u/notes.txt'), null);
  });

  it('does not expose $HOME through protectHome read-only alone', () => {
    // The engine mounts $HOME, but Landlock still limits reads to the
    // configured paths, so the home directory is readable only when it is one.
    const { visible } = linuxView({ protectHome: 'read-only' });
    strict.equal(visible('/home/u/notes.txt'), null);
    const granted = linuxView({ readPaths: ['/usr', '/home/u'], protectHome: 'read-only' });
    strict.equal(granted.visible('/home/u/notes.txt'), '/home/u/notes.txt');
  });

  it('does not count the working directory unless it is a configured path', () => {
    const { visible } = linuxView({ readPaths: ['/usr'] });
    strict.equal(visible('/srv/proj/libplugin.so'), null);
  });

  it('reports nothing readable in dry-run and everything in learn mode', () => {
    strict.equal(linuxView({ enableDryRun: true }).visible('/usr/lib/libc.so.6'), null);
    strict.equal(linuxView({ enableLearn: true }).visible('/etc/shadow'), '/etc/shadow');
  });

  it('collapses nested roots and freezes the view', () => {
    const { view } = linuxView();
    strict.ok(view.readRoots.includes('/usr'));
    strict.ok(!view.readRoots.includes('/usr/lib'));
    strict.ok(Object.isFrozen(view));
    strict.ok(Object.isFrozen(view.readRoots));
    strict.throws(() => { view.readRoots.push('/'); });
  });
});

const darwinTree = {
  '/private/tmp/proj/lib.dylib': 'file',
  '/private/tmp/proj/.git/config': 'file',
  '/private/tmp/proj/link': '->/Users/u/.aws/credentials',
  '/tmp': '->/private/tmp',
  '/Users/u/.aws/credentials': 'file',
  '/Users/u/work/app/x.dylib': 'file',
  '/Users/u/work/app/data.txt': 'file',
  '/Users/u/Library/Keychains/login.keychain-db': 'file',
  '/Users/u/Library/Caches/safer-exec-runs/1-2.json': 'file',
  '/private/etc/hosts': 'file',
  '/private/etc/master.passwd': 'file',
  '/usr/lib/libSystem.B.dylib': 'file',
  '/System/Library/Tcl/8.5/ffidl.dylib': 'file',
  '/Users/u/elsewhere/z': 'file',
};

function darwinView(overrides = {}) {
  const fs = fakeFs(darwinTree);
  const view = buildFilesystemView({
    platform: 'darwin',
    readPaths: [],
    writePaths: [],
    workingDir: '/tmp/proj',
    home: '/Users/u',
    tmpDir: '/tmp',
    ...overrides,
  }, fs);
  return { view, visible: (p) => resolveVisiblePathInView(view, p, fs) };
}

describe('buildFilesystemView: darwin', () => {
  it('matches the resolved path against the profile', () => {
    const { visible } = darwinView();
    strict.equal(visible('/tmp/proj/lib.dylib'), '/private/tmp/proj/lib.dylib');
    strict.equal(visible('/private/etc/hosts'), '/private/etc/hosts');
    strict.equal(visible('/usr/lib/libSystem.B.dylib'), '/usr/lib/libSystem.B.dylib');
  });

  it('rejects hidden components unless hidden paths are allowed', () => {
    strict.equal(darwinView().visible('/tmp/proj/.git/config'), null);
    strict.equal(
      darwinView({ allowHidden: true }).visible('/tmp/proj/.git/config'),
      '/private/tmp/proj/.git/config'
    );
  });

  it('rejects a link in the project that points at a hidden file', () => {
    strict.equal(darwinView().visible('/tmp/proj/link'), null);
    strict.equal(darwinView({ allowHidden: true }).visible('/tmp/proj/link'), null);
  });

  it('applies the credential-store and registry denies under granted roots', () => {
    const { visible } = darwinView({ readPaths: ['/Users/u'] });
    strict.equal(visible('/Users/u/work/app/data.txt'), '/Users/u/work/app/data.txt');
    strict.equal(visible('/Users/u/Library/Keychains/login.keychain-db'), null);
    strict.equal(visible('/Users/u/Library/Caches/safer-exec-runs/1-2.json'), null);
    strict.equal(visible('/private/etc/master.passwd'), null);
  });

  it('applies the blockInterpreters read denies', () => {
    const opts = { writePaths: ['/Users/u/work/app'], blockInterpreters: true };
    const { visible } = darwinView(opts);
    strict.equal(visible('/System/Library/Tcl/8.5/ffidl.dylib'), null);
    strict.equal(visible('/Users/u/work/app/x.dylib'), null);
    strict.equal(visible('/Users/u/work/app/data.txt'), '/Users/u/work/app/data.txt');
    const relaxed = darwinView({ ...opts, allowWritableDylibLoad: true });
    strict.equal(relaxed.visible('/Users/u/work/app/x.dylib'), '/Users/u/work/app/x.dylib');
  });

  it('rejects paths outside every allowed root', () => {
    strict.equal(darwinView().visible('/Users/u/elsewhere/z'), null);
  });

  it('limits dry-run to the bootstrap paths', () => {
    const { visible } = darwinView({ enableDryRun: true });
    strict.equal(visible('/usr/lib/libSystem.B.dylib'), '/usr/lib/libSystem.B.dylib');
    strict.equal(visible('/tmp/proj/lib.dylib'), null);
  });
});

describe('buildFilesystemView: win32', () => {
  const files = new Set([
    'C:\\Windows\\System32\\kernel32.dll',
    'C:\\proj\\plugin.dll',
    'C:\\Users\\u\\.aws\\credentials',
    'D:\\data.bin',
  ]);
  const dirs = ['C:\\Windows', 'C:\\proj', 'C:\\Users\\u', 'D:\\', 'C:\\'];
  const fs = {
    realpath: (p) => {
      const hit = [...files, ...dirs].find((f) => f.toLowerCase() === p.toLowerCase());
      if (!hit) {
        throw new Error('ENOENT');
      }
      return hit;
    },
    lstat: () => ({ isSymbolicLink: () => false }),
    exists: (p) => [...files, ...dirs].some((f) => f.toLowerCase() === p.toLowerCase()),
  };
  const make = (overrides = {}) => {
    const view = buildFilesystemView({
      platform: 'win32',
      readPaths: [],
      writePaths: [],
      workingDir: 'C:\\proj',
      systemRoot: 'C:\\Windows',
      ...overrides,
    }, fs);
    return (p) => resolveVisiblePathInView(view, p, fs);
  };

  it('covers SystemRoot and the working directory, case-insensitively', () => {
    const visible = make();
    strict.equal(visible('c:\\windows\\system32\\KERNEL32.dll'), 'C:\\Windows\\System32\\kernel32.dll');
    strict.equal(visible('C:\\proj\\plugin.dll'), 'C:\\proj\\plugin.dll');
    strict.equal(visible('C:\\Users\\u\\.aws\\credentials'), null);
  });

  it('does not extend a volume-root grant to its subdirectories', () => {
    strict.equal(make({ readPaths: ['D:\\'] })('D:\\data.bin'), null);
  });

  it('drops the read and write grants in dry-run', () => {
    strict.equal(make({ readPaths: ['C:\\Users\\u'] })('C:\\Users\\u\\.aws\\credentials'), 'C:\\Users\\u\\.aws\\credentials');
    strict.equal(make({ readPaths: ['C:\\Users\\u'], enableDryRun: true })('C:\\Users\\u\\.aws\\credentials'), null);
  });
});

describe('buildFilesystemView: other platforms', () => {
  it('reports nothing readable where the rules are not modeled', () => {
    const fs = fakeFs({ '/usr/lib/x': 'file' });
    const view = buildFilesystemView({ platform: 'freebsd', readPaths: ['/usr'] }, fs);
    strict.equal(view.modeled, false);
    strict.equal(resolveVisiblePathInView(view, '/usr/lib/x', fs), null);
  });
});

describe('SaferExec filesystem visibility', () => {
  it('describes the current settings before a run', () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'safer-exec-vis-')));
    try {
      writeFileSync(join(dir, 'a.so'), 'x');
      const exec = new SaferExec().workingDir(dir);
      const view = exec.filesystemView();
      strict.equal(view.platform, process.platform);
      strict.equal(exec.resolveVisiblePath(join(dir, 'a.so')) !== null, exec.isPathVisible(join(dir, 'a.so')));
      if (['linux', 'darwin'].includes(process.platform)) {
        strict.equal(exec.isPathVisible(join(dir, 'a.so')), true);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('keeps the view recorded when the run was prepared', async () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'safer-exec-vis-')));
    try {
      writeFileSync(join(dir, 'a.so'), 'x');
      const exec = new SaferExec().workingDir(dir);
      await exec._buildConfig('true', []);
      const recorded = exec.filesystemView();
      exec.readPaths('/').allowHidden(true);
      strict.equal(exec.filesystemView(), recorded);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('does not change the instance or the filesystem', () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'safer-exec-vis-')));
    try {
      symlinkSync(join(dir, 'nowhere'), join(dir, 'dangling'));
      const exec = new SaferExec().workingDir(dir);
      const before = JSON.stringify({ r: exec._readPaths, w: exec._writePaths });
      strict.equal(exec.isPathVisible(join(dir, 'dangling')), false);
      exec.filesystemView();
      strict.equal(JSON.stringify({ r: exec._readPaths, w: exec._writePaths }), before);
      strict.equal(exec._lastFilesystemView, undefined);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
