/**
 * Host filesystem visibility of a sandboxed run.
 *
 * The engines decide what a workload can read from the host: bind mounts and
 * Landlock rules on Linux, a Seatbelt profile on macOS, and container grants
 * on Windows. A caller that acts on paths reported by the workload (for
 * example, hashing the libraries a traced program loaded) needs to know
 * whether those paths were readable inside the sandbox, because a workload can
 * report, or leave a symbolic link at, a path the sandbox hid from it.
 *
 * This module models those rules from the same configuration the engine
 * receives. The model is conservative: where it cannot tell whether a path was
 * readable, it answers that it was not.
 *
 * @module visibility
 */

import { lstatSync, realpathSync, statSync } from 'node:fs';
import { posix, win32 } from 'node:path';

/**
 * Directories the macOS engine always allows reads from (`systemReadPaths` in
 * `engine_darwin.go`).
 */
const DARWIN_SYSTEM_READ_PATHS = [
  '/System', '/usr/lib', '/usr/share', '/bin', '/sbin',
  '/usr/bin', '/usr/sbin', '/private/etc', '/private/var',
  '/dev', '/Library', '/opt/homebrew', '/usr/local/Cellar',
];

/** Directories the macOS dry-run profile allows reads from. */
const DARWIN_DRY_RUN_READ_PATHS = ['/usr/lib', '/System', '/dev', '/private/var/db/dyld'];

/** Credential stores the macOS engine denies regardless of other grants. */
const DARWIN_SENSITIVE_DENIES = [
  '/Library/Keychains',
  '/private/var/db/dslocal',
  '/private/etc/master.passwd',
  '/private/var/db/sudo',
  '/private/var/db/ConfigurationProfiles',
];

/** Home-relative credential stores the macOS engine denies. */
const DARWIN_SENSITIVE_HOME_DENIES = [
  'Library/Keychains',
  'Library/Cookies',
  'Library/Application Support/com.apple.TCC',
  'Library/Application Support/Google/Chrome',
  'Library/Application Support/Firefox',
];

/** Paths denied by `.blockCrypto()` on macOS. */
const DARWIN_CRYPTO_DENIES = [
  '/usr/lib/system/libcommonCrypto.dylib',
  '/usr/lib/libcrypto',
  '/usr/lib/libssl',
  '/etc/ssl',
  '/private/etc/ssl',
  '/etc/security',
  '/private/etc/security',
  '/System/Library/Frameworks/Security.framework',
];

/** Tcl/Tk trees denied by `.blockInterpreters()` on macOS. */
const DARWIN_INTERPRETER_READ_DENIES = [
  '/System/Library/Tcl',
  '/System/Library/Frameworks/Tcl.framework',
  '/System/Library/Frameworks/Tk.framework',
];

/** Default filesystem probes. Tests replace them to model other hosts. */
const defaultFs = {
  realpath: (p) => realpathSync.native(p),
  lstat: (p) => lstatSync(p),
  exists: (p) => {
    try {
      statSync(p);
      return true;
    } catch {
      return false;
    }
  },
};

function tryRealpath(fs, p) {
  try {
    return fs.realpath(p);
  } catch {
    return null;
  }
}

function pathOps(platform) {
  return platform === 'win32' ? win32 : posix;
}

/**
 * Normalizes a path for prefix comparison: absolute, no trailing separator,
 * and lower case with backslashes on Windows.
 *
 * @param {string} platform
 * @param {string} p
 * @returns {string|null} The normalized path, or null when `p` is not absolute
 */
function normalize(platform, p) {
  if (typeof p !== 'string' || p === '') {
    return null;
  }
  const ops = pathOps(platform);
  if (!ops.isAbsolute(p)) {
    return null;
  }
  let n = ops.resolve(p);
  if (platform === 'win32') {
    n = n.toLowerCase();
  }
  return n;
}

function isRoot(platform, p) {
  return pathOps(platform).parse(p).root === p;
}

/**
 * Reports whether `p` equals `root` or lies beneath it. Both arguments must
 * already be normalized.
 *
 * @param {string} platform
 * @param {string} p
 * @param {string} root
 * @returns {boolean}
 */
function isUnder(platform, p, root) {
  if (p === root) {
    return true;
  }
  const sep = pathOps(platform).sep;
  const prefix = root.endsWith(sep) ? root : root + sep;
  return p.startsWith(prefix);
}

function underAny(platform, p, roots) {
  return roots.some((r) => isUnder(platform, p, r));
}

function uniq(list) {
  return Array.from(new Set(list.filter(Boolean)));
}

/**
 * Drops roots that lie beneath another root and sorts the rest. Not used on
 * Windows, where a volume-root grant does not cover its subdirectories.
 */
function collapseRoots(platform, roots) {
  return roots
    .filter((r) => !roots.some((o) => o !== r && isUnder(platform, r, o)))
    .sort();
}

/**
 * Returns the subtrees covered by both root lists: for each pair, the deeper
 * root when one contains the other.
 */
function intersectRoots(platform, a, b) {
  const out = [];
  for (const x of a) {
    for (const y of b) {
      if (isUnder(platform, x, y)) {
        out.push(x);
      } else if (isUnder(platform, y, x)) {
        out.push(y);
      }
    }
  }
  return uniq(out);
}

/**
 * Models the Linux engine. A host path is readable only when both layers the
 * engine applies would allow it:
 *
 * - the bind mounts of `setupFilesystem` (full isolation), after
 *   `protectSystem`, `protectHome`, the working directory and the tmpfs that
 *   `privateTmp` and `protectHome: 'tmpfs'` mount over `/tmp`, `/var/tmp` and
 *   `$HOME`; and
 * - the Landlock rules on the configured read and write paths, which are the
 *   only filesystem restriction in reduced isolation.
 *
 * Requiring both keeps the answer correct whichever mode the engine ends up
 * in, at the cost of answering "not readable" for a path only one mode would
 * expose.
 */
function linuxView(input, fs) {
  const platform = 'linux';
  const view = baseView(input);
  if (input.enableLearn) {
    view.readRoots = ['/'];
    view.writeRoots = ['/'];
    return view;
  }
  if (input.enableDryRun) {
    return view;
  }
  const norm = (p) => normalize(platform, p);
  const read = uniq(input.readPaths.map(norm));
  const write = uniq(input.writePaths.map(norm));

  const mountRead = [...read];
  let mountWrite = [...write];
  if (input.protectSystem === 'strict' || input.protectSystem === 'full') {
    for (const p of ['/usr', '/boot', '/etc', '/lib', '/lib64']) {
      if (!mountRead.includes(p) && fs.exists(p)) {
        mountRead.push(p);
      }
    }
  }
  const cwd = norm(input.workingDir || input.cwd);
  if (cwd && !mountWrite.includes(cwd)) {
    mountWrite.push(cwd);
  }
  const home = norm(input.home);
  let mountReadFinal = mountRead;
  if (home && input.protectHome === 'read-only') {
    if (!mountReadFinal.includes(home)) {
      mountReadFinal = [...mountReadFinal, home];
    }
    mountWrite = mountWrite.filter((p) => !isUnder(platform, p, home));
  } else if (home && input.protectHome === 'tmpfs') {
    mountReadFinal = mountReadFinal.filter((p) => !isUnder(platform, p, home));
    mountWrite = mountWrite.filter((p) => !isUnder(platform, p, home));
  }

  const covered = [];
  if (input.privateTmp) {
    covered.push('/tmp', '/var/tmp');
  }
  if (home && input.protectHome === 'tmpfs') {
    covered.push(home);
  }

  const allMountPaths = [...mountReadFinal, ...mountWrite];
  const mountSource = (p) => {
    if (p === '/' || underAny(platform, p, covered)) {
      return null;
    }
    let st;
    try {
      st = fs.lstat(p);
    } catch {
      return null;
    }
    const resolved = tryRealpath(fs, p);
    if (!resolved) {
      return null;
    }
    if (st.isSymbolicLink() && !underAny(platform, resolved, allMountPaths)) {
      return null;
    }
    return norm(resolved);
  };
  const mountReadSources = uniq(allMountPaths.map(mountSource));
  const mountWriteSources = uniq(mountWrite.map(mountSource));

  const landlock = (list) => uniq(list.filter((p) => fs.exists(p)).map((p) => norm(tryRealpath(fs, p))));
  const landlockRead = landlock([...read, ...write]);
  const landlockWrite = landlock(write);

  view.readRoots = intersectRoots(platform, mountReadSources, landlockRead);
  view.writeRoots = intersectRoots(platform, mountWriteSources, landlockWrite);
  view.deniedRoots = uniq(covered.flatMap((p) => [p, norm(tryRealpath(fs, p))]));
  return view;
}

/**
 * Models the macOS Seatbelt profile built by `buildSeatbeltProfile` (or the
 * dry-run and learn profiles). Seatbelt matches rules against the resolved
 * path of the file being opened and does not resolve the paths in its rules,
 * so allow rules are kept as written. Deny rules are matched both as written
 * and resolved, which can only widen what is denied.
 */
function darwinView(input, fs) {
  const platform = 'darwin';
  const view = baseView(input);
  const norm = (p) => normalize(platform, p);
  if (input.enableLearn) {
    view.readRoots = ['/'];
    view.writeRoots = ['/'];
    return view;
  }
  if (input.enableDryRun) {
    const roots = [...DARWIN_DRY_RUN_READ_PATHS];
    if (posix.isAbsolute(input.cmd || '')) {
      roots.push(posix.dirname(input.cmd));
    }
    view.readRoots = uniq(roots.map(norm));
    return view;
  }

  const tempDirs = ['/private/tmp', '/tmp', input.tmpDir];
  const reads = [...DARWIN_SYSTEM_READ_PATHS, ...tempDirs, ...input.readPaths, ...input.writePaths];
  if (posix.isAbsolute(input.cmd || '')) {
    reads.push(input.cmd);
  }
  if (input.workingDir) {
    reads.push(input.workingDir);
  }
  view.readRoots = uniq(reads.map(norm));
  view.writeRoots = uniq([...tempDirs, ...input.writePaths].map(norm));

  const denies = [...DARWIN_SENSITIVE_DENIES];
  const home = norm(input.home);
  if (home) {
    for (const rel of DARWIN_SENSITIVE_HOME_DENIES) {
      denies.push(posix.join(home, rel));
    }
    denies.push(posix.join(home, 'Library/Caches/safer-exec-runs'));
  } else if (input.tmpDir) {
    denies.push(posix.join(input.tmpDir, `safer-exec-runs-${input.uid}`));
  }
  if (input.blockCrypto) {
    denies.push(...DARWIN_CRYPTO_DENIES);
  }
  if (input.blockCryptoEntropy) {
    denies.push('/dev/random', '/dev/urandom', '/dev/random.entropy');
  } else if (input.blockTPM) {
    denies.push('/dev/tpm0', '/dev/tpmrm0');
  } else if (!input.allowGPU) {
    denies.push('/dev/dri', '/dev/opencl');
  }
  if (input.blockInterpreters) {
    denies.push(...DARWIN_INTERPRETER_READ_DENIES);
    if (!input.allowWritableDylibLoad) {
      const trees = [...tempDirs, ...input.writePaths].map(norm).filter(Boolean);
      view.deniedDylibTrees = uniq(trees.flatMap((t) => [t, norm(tryRealpath(fs, t))]));
    }
  }
  view.deniedRoots = uniq(denies.map(norm).flatMap((p) => [p, norm(tryRealpath(fs, p))]));
  view.denyHidden = !input.allowHidden;
  return view;
}

/**
 * Models the Windows container grants built by `internal/mxc/translate.go`:
 * `%SystemRoot%`, the read and write paths, and the working directory. The
 * program's own directory is also granted by the engine, but it is resolved
 * there from `PATH`, so it is left out here. A grant on a volume root does not
 * extend to its subdirectories.
 */
function windowsView(input, fs) {
  const platform = 'win32';
  const view = baseView(input);
  const norm = (p) => normalize(platform, p);
  const canon = (p) => {
    const n = norm(p);
    if (!n) {
      return null;
    }
    const real = tryRealpath(fs, p);
    return real ? norm(real) : null;
  };
  const grantsRead = input.enableDryRun ? [] : [...input.readPaths, ...input.writePaths];
  const grantsWrite = input.enableDryRun ? [] : [...input.writePaths];
  view.readRoots = uniq([input.systemRoot, input.workingDir || input.cwd, ...grantsRead].map(canon));
  view.writeRoots = uniq(grantsWrite.map(canon));
  view.caseInsensitive = true;
  return view;
}

function baseView(input) {
  return {
    platform: input.platform,
    mode: input.enableLearn ? 'learn' : input.enableDryRun ? 'dry-run' : 'enforce',
    modeled: true,
    readRoots: [],
    writeRoots: [],
    deniedRoots: [],
    deniedDylibTrees: [],
    denyHidden: false,
    caseInsensitive: false,
  };
}

/**
 * Builds the host filesystem view of a sandboxed run.
 *
 * @param {Object} input - The effective configuration (see `SaferExec#filesystemView`)
 * @param {Object} [fs] - Filesystem probes (`realpath`, `lstat`, `exists`); tests replace them
 * @returns {FilesystemView} A frozen description of what the workload could read
 */
export function buildFilesystemView(input, fs = defaultFs) {
  const filled = {
    readPaths: [],
    writePaths: [],
    ...input,
  };
  let view;
  switch (filled.platform) {
    case 'linux':
      view = linuxView(filled, fs);
      break;
    case 'darwin':
      view = darwinView(filled, fs);
      break;
    case 'win32':
      view = windowsView(filled, fs);
      break;
    default:
      view = { ...baseView(filled), modeled: false };
  }
  if (view.platform !== 'win32') {
    view.readRoots = collapseRoots(view.platform, view.readRoots);
    view.writeRoots = collapseRoots(view.platform, view.writeRoots);
  }
  for (const key of ['readRoots', 'writeRoots', 'deniedRoots', 'deniedDylibTrees']) {
    Object.freeze(view[key]);
  }
  return Object.freeze(view);
}

/**
 * Resolves `path` on the host and returns the resolved path when the sandbox
 * described by `view` allowed the workload to read it, or null otherwise.
 *
 * The path must be absolute. Every symbolic link is resolved first, so a link
 * that points from a readable directory to a hidden file is reported as not
 * readable. Callers that go on to open the file should open the returned path,
 * not the one they passed in.
 *
 * @param {FilesystemView} view - From {@link buildFilesystemView}
 * @param {string} path - Absolute host path
 * @param {Object} [fs] - Filesystem probes; tests replace them
 * @returns {string|null}
 */
export function resolveVisiblePathInView(view, path, fs = defaultFs) {
  if (!view || !view.modeled || typeof path !== 'string') {
    return null;
  }
  const platform = view.platform;
  if (!pathOps(platform).isAbsolute(path) || path.includes('\0')) {
    return null;
  }
  const real = tryRealpath(fs, path);
  if (!real) {
    return null;
  }
  const p = normalize(platform, real);
  if (!p) {
    return null;
  }
  const allowed = view.readRoots.some((root) => {
    if (platform === 'win32' && isRoot(platform, root)) {
      return p === root;
    }
    return isUnder(platform, p, root);
  });
  if (!allowed) {
    return null;
  }
  if (underAny(platform, p, view.deniedRoots)) {
    return null;
  }
  if (view.denyHidden && p.split('/').some((part) => part.length > 1 && part.startsWith('.'))) {
    return null;
  }
  if (view.deniedDylibTrees.length && p.endsWith('.dylib')
    && view.deniedDylibTrees.some((t) => p !== t && isUnder(platform, p, t))) {
    return null;
  }
  return real;
}

/**
 * @typedef {Object} FilesystemView
 * @property {string} platform - `process.platform` the view describes
 * @property {'enforce'|'learn'|'dry-run'} mode - Sandbox mode of the run
 * @property {boolean} modeled - False on platforms whose rules are not modeled; nothing is then reported readable
 * @property {ReadonlyArray<string>} readRoots - Host directories and files the workload could read, with everything beneath them
 * @property {ReadonlyArray<string>} writeRoots - Host directories and files the workload could write
 * @property {ReadonlyArray<string>} deniedRoots - Subtrees removed from the read roots
 * @property {ReadonlyArray<string>} deniedDylibTrees - Trees in which `.dylib` files were unreadable (macOS `.blockInterpreters()`)
 * @property {boolean} denyHidden - Whether any path component starting with a dot was unreadable (macOS without `.allowHidden()`)
 * @property {boolean} caseInsensitive - Whether the roots are lower-cased for comparison (Windows)
 */
