#!/usr/bin/env node
/**
 * One-time setup for npm packages that the release workflow publishes but
 * that do not exist on the registry yet.
 *
 * npm trusted publishing (OIDC from GitHub Actions) can only be configured
 * for a package that already exists, so a brand-new package name needs:
 *
 *   1. a first publish from a maintainer's machine (a placeholder version),
 *   2. a trusted-publisher entry tying it to this repository's workflow,
 *   3. optionally, a deprecation notice on the placeholder version.
 *
 * Every step that changes the registry is a dry run unless --yes is given.
 * The script never reads or stores credentials: run `npm login` yourself
 * first, and npm prompts for your 2FA code (or opens the browser) itself.
 *
 * Usage:
 *   node bootstrap.mjs check
 *   node bootstrap.mjs publish   [--yes] [--package <name>...]
 *   node bootstrap.mjs trust     [--yes] [--package <name>...]
 *   node bootstrap.mjs deprecate [--yes] [--package <name>...]
 *   node bootstrap.mjs all       [--yes] [--package <name>...]
 *
 * Requires Node.js 20+ and npm 11.15+ (for `npm trust`).
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

// The packages this repository's release workflow publishes for the first
// time, with the platform fields the workflow gives them.
const PACKAGES = {
  '@cdxgen/safer-exec-windows-amd64': { os: 'win32', cpu: 'x64' },
  '@cdxgen/safer-exec-windows-arm64': { os: 'win32', cpu: 'arm64' },
};

// Where the trusted publisher lives: .github/workflows/ci.yml in this repo,
// the workflow whose publish job runs `npm publish --provenance`.
const REPOSITORY = 'cdxgen/safer-exec';
const WORKFLOW_FILE = 'ci.yml';
// A package that is already published through the same workflow; `check`
// shows its trust configuration so the new entries can be compared with it.
const REFERENCE_PACKAGE = '@cdxgen/safer-exec';

const PLACEHOLDER_VERSION = '0.0.0';
const DEPRECATION_MESSAGE =
  'Placeholder published to set up trusted publishing. Install @cdxgen/safer-exec, which pulls in the matching platform package.';

const MIN_NPM = [11, 15, 0];

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    yes: { type: 'boolean', default: false },
    package: { type: 'string', multiple: true },
    help: { type: 'boolean', short: 'h', default: false },
  },
});

const command = positionals[0] ?? 'check';
if (values.help || !['check', 'publish', 'trust', 'deprecate', 'all'].includes(command)) {
  console.log(
    'Usage: node bootstrap.mjs <check|publish|trust|deprecate|all> [--yes] [--package <name>...]',
  );
  process.exit(values.help ? 0 : 2);
}

const selected = values.package?.length ? values.package : Object.keys(PACKAGES);
for (const name of selected) {
  if (!PACKAGES[name]) {
    console.error(`Unknown package ${name}. Known: ${Object.keys(PACKAGES).join(', ')}`);
    process.exit(2);
  }
}
const apply = values.yes;

/**
 * Runs npm with the given arguments. Arguments are fixed strings from this
 * script, never user input, so a shell is only used where Windows requires
 * one to start npm.cmd.
 *
 * @param {string[]} args
 * @param {{capture?: boolean, cwd?: string}} [options]
 * @returns {{status: number, stdout: string, stderr: string}}
 */
function npm(args, { capture = false, cwd } = {}) {
  const res = spawnSync('npm', args, {
    cwd,
    encoding: 'utf8',
    stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
    shell: process.platform === 'win32',
  });
  if (res.error) {
    throw res.error;
  }
  return { status: res.status ?? 1, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

function heading(text) {
  console.log(`\n== ${text}`);
}

function npmVersionOK() {
  const v = npm(['--version'], { capture: true }).stdout.trim();
  const parts = v.split('.').map((n) => Number.parseInt(n, 10));
  for (let i = 0; i < MIN_NPM.length; i++) {
    if ((parts[i] ?? 0) !== MIN_NPM[i]) {
      return { ok: (parts[i] ?? 0) > MIN_NPM[i], version: v };
    }
  }
  return { ok: true, version: v };
}

function whoami() {
  const res = npm(['whoami'], { capture: true });
  return res.status === 0 ? res.stdout.trim() : '';
}

function publishedVersions(name) {
  const res = npm(['view', name, 'versions', '--json'], { capture: true });
  if (res.status !== 0) {
    return null; // E404: not on the registry yet
  }
  const parsed = JSON.parse(res.stdout || '[]');
  return Array.isArray(parsed) ? parsed : [parsed];
}

function trustList(name) {
  const res = npm(['trust', 'list', name, '--json'], { capture: true });
  if (res.status !== 0) {
    return { error: (res.stderr.match(/npm error (?!code).*$/m)?.[0] ?? res.stderr).trim() };
  }
  return { entries: JSON.parse(res.stdout || '[]') };
}

function check() {
  heading('Environment');
  const { ok, version } = npmVersionOK();
  console.log(`npm ${version}${ok ? '' : ` (too old: npm trust needs ${MIN_NPM.join('.')} or later; run npm install -g npm@latest)`}`);
  const user = whoami();
  console.log(user ? `logged in to npm as ${user}` : 'not logged in to npm: run `npm login` (account 2FA must be on)');

  heading(`Reference: ${REFERENCE_PACKAGE}`);
  if (user) {
    const ref = trustList(REFERENCE_PACKAGE);
    console.log(ref.error ? `trust list failed: ${ref.error}` : JSON.stringify(ref.entries, null, 2));
  } else {
    console.log('(log in to see its trusted-publisher configuration)');
  }

  for (const name of selected) {
    heading(name);
    const versions = publishedVersions(name);
    console.log(versions ? `published versions: ${versions.join(', ')}` : 'not on the registry yet (needs `publish`)');
    if (versions && user) {
      const trust = trustList(name);
      if (trust.error) {
        console.log(`trust list failed: ${trust.error}`);
      } else if (!trust.entries.length) {
        console.log('no trusted publisher yet (needs `trust`)');
      } else {
        console.log(`trusted publisher: ${JSON.stringify(trust.entries)}`);
      }
    }
  }
  return ok && Boolean(user);
}

function publish(name) {
  heading(`publish ${name}@${PLACEHOLDER_VERSION}`);
  const versions = publishedVersions(name);
  if (versions) {
    console.log(`already on the registry (${versions.join(', ')}); nothing to do`);
    return true;
  }
  const { os, cpu } = PACKAGES[name];
  const dir = mkdtempSync(join(tmpdir(), 'safer-exec-npm-bootstrap-'));
  try {
    writeFileSync(
      join(dir, 'package.json'),
      `${JSON.stringify(
        {
          name,
          version: PLACEHOLDER_VERSION,
          description: `Placeholder for the safer-exec ${os}-${cpu} engine. Install @cdxgen/safer-exec instead.`,
          license: 'MIT',
          repository: { type: 'git', url: `git+https://github.com/${REPOSITORY}.git` },
          homepage: `https://github.com/${REPOSITORY}#readme`,
          os: [os],
          cpu: [cpu],
          files: ['README.md'],
        },
        null,
        2,
      )}\n`,
    );
    writeFileSync(
      join(dir, 'README.md'),
      `# ${name}\n\nThis version is a placeholder, published once so that the package can be tied to the\n` +
        `${REPOSITORY} release workflow through npm trusted publishing. It contains no code.\n\n` +
        'Install `@cdxgen/safer-exec`; it pulls in the matching platform package.\n',
    );
    const args = ['publish', '--access', 'public'];
    if (!apply) {
      args.push('--dry-run');
      console.log('(dry run; add --yes to publish)');
    }
    return npm(args, { cwd: dir }).status === 0;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Waits for a just-published package to become visible on the registry,
 * which can take a little while after `npm publish` returns.
 *
 * @param {string} name
 * @returns {string[] | null}
 */
function waitForPackage(name) {
  for (let attempt = 0; attempt < 12; attempt++) {
    const versions = publishedVersions(name);
    if (versions || !apply) {
      return versions;
    }
    console.log('waiting for the registry to list the package...');
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5000);
  }
  return null;
}

function trust(name) {
  heading(`trust ${name} -> ${REPOSITORY} .github/workflows/${WORKFLOW_FILE}`);
  if (!waitForPackage(name)) {
    console.log(apply ? 'not on the registry yet; run `publish --yes` first' : 'not on the registry yet (would fail until `publish --yes` has run)');
    return !apply;
  }
  const existing = trustList(name);
  if (existing.entries?.length) {
    console.log(`already configured: ${JSON.stringify(existing.entries)}`);
    return true;
  }
  const args = ['trust', 'github', name, '--repository', REPOSITORY, '--file', WORKFLOW_FILE, '--allow-publish'];
  if (apply) {
    args.push('--yes');
  } else {
    args.push('--dry-run');
    console.log('(dry run; add --yes to create the trust relationship)');
  }
  return npm(args).status === 0;
}

function deprecate(name) {
  heading(`deprecate ${name}@${PLACEHOLDER_VERSION}`);
  const versions = publishedVersions(name);
  if (!versions?.includes(PLACEHOLDER_VERSION)) {
    console.log('no placeholder version on the registry; nothing to do');
    return true;
  }
  if (!apply) {
    console.log(`(dry run; add --yes to run: npm deprecate ${name}@${PLACEHOLDER_VERSION} "${DEPRECATION_MESSAGE}")`);
    return true;
  }
  return npm(['deprecate', `${name}@${PLACEHOLDER_VERSION}`, DEPRECATION_MESSAGE]).status === 0;
}

let ok = true;
switch (command) {
  case 'check':
    ok = check();
    break;
  case 'publish':
    ok = selected.every(publish);
    break;
  case 'trust':
    ok = selected.every(trust);
    break;
  case 'deprecate':
    ok = selected.every(deprecate);
    break;
  case 'all':
    if (apply && !check()) {
      console.error('\nFix the environment above before running with --yes.');
      process.exit(1);
    }
    ok = selected.every((name) => publish(name) && trust(name) && deprecate(name));
    if (apply) {
      check();
    }
    break;
}
process.exit(ok ? 0 : 1);
