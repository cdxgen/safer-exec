/**
 * NuGet / .NET ecosystem policy.
 *
 * Hardened profile for running dotnet CLI commands (restore, build, publish).
 * Covers:
 * - NuGet v3 service index and package CDN hosts
 * - .NET SDK/runtime download hosts (post azureedge retirement, 2025)
 * - dotnet installation and cache directories
 * - SSL certificate paths
 *
 * Host notes: dotnet restore needs api.nuget.org (service index) AND
 * globalcdn.nuget.org (package downloads resolved via the service index —
 * NU1301 "Unable to load the service index" is the classic symptom of
 * blocking either). The legacy dotnetcli.azureedge.net / dotnetbuilds.
 * azureedge.net CDN domains were retired in January 2025 and were replaced
 * by builds.dotnet.microsoft.com.
 *
 * @module policies/nuget
 */

import { join } from 'node:path';
import { existsSync } from 'node:fs';
import { getSslPaths } from './sslhelper.js';

function getDotnetDirs() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const dirs = [];
  if (home) {
    dirs.push(join(home, '.dotnet'));
    dirs.push(join(home, '.nuget'));
    // Non-Windows per-user NuGet caches
    dirs.push(join(home, '.local', 'share', 'NuGet'));
  }
  if (process.platform === 'darwin') {
    dirs.push('/usr/local/share/dotnet');
    dirs.push('/opt/homebrew/share/dotnet');
  } else if (process.platform === 'linux') {
    dirs.push('/usr/share/dotnet');
    dirs.push('/usr/lib/dotnet');
  }
  return dirs.filter(p => existsSync(p));
}

export function nugetPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();

  const writePaths = [
    join(cwd, 'obj'),
    join(cwd, 'bin'),
  ];
  if (home) {
    writePaths.push(join(home, '.nuget', 'packages'));
    writePaths.push(join(home, '.local', 'share', 'NuGet'));
    // First-run SDK state (telemetry sentinel, dotnet-cli home fallback)
    writePaths.push(join(home, '.dotnet'));
  }
  writePaths.push(join(cwd, 'artifacts'));

  return {
    allowHosts: [
      'api.nuget.org',
      'globalcdn.nuget.org',
      'nuget.org',
      'builds.dotnet.microsoft.com',
    ],

    readPaths: [
      ...getDotnetDirs(),
      ...getSslPaths(),
      join(cwd, 'nuget.config'),
      join(cwd, 'NuGet.config'),
      join(cwd, 'global.json'),
    ],

    writePaths,

    env: {
      DOTNET_CLI_TELEMETRY_OPTOUT: '1',
      DOTNET_NOLOGO: '1',
      DOTNET_SKIP_FIRST_TIME_EXPERIENCE: '1',
      NUGET_XMLDOC_MODE: 'skip',
    },

    // dotnet's layout is dotfile-heavy: the SDK reads sdk/<ver>/.version at
    // startup, and every cache/config dir is hidden (~/.dotnet, ~/.nuget).
    // Without this, the default hidden-path deny breaks `dotnet restore`
    // before it reaches the network.
    allowHidden: true,

    // dotnet/MSBuild spawn worker nodes (MSBuild node reuse, VBCSCompiler
    // build server), so fork/exec must stay available.
    blockFork: false,
    blockExec: [],

    // macOS: .NET evaluates TLS trust through securityd rather than reading
    // the cert files, and resolves the home directory via getpwuid() instead
    // of $HOME. Without these mach-lookups `dotnet restore` fails with "bad
    // certificate format" and scatters its caches into the working directory.
    // This is the one bundled policy that opts in — see allowSecurityServices()
    // for what it exposes.
    allowSecurityServices: true,

    denyPersistenceWrites: true,
    blockInterpreters: true,
  };
}

export default nugetPolicy;
