# Builds the Microsoft eXecution Container (MXC) executor, wxc-exec.exe, from a
# pinned commit of https://github.com/microsoft/mxc for the safer-exec Windows
# engine.
#
# Only wxc-exec.exe is shipped. The other MXC host binaries are not needed on
# the BaseContainer tier safer-exec targets, and they would introduce UAC
# elevation into an unattended tool: winhttp-proxy-shim.exe (per-container
# proxy on the legacy AppContainer tiers), plm.exe (elevated WPR capture
# fallback) and wxc-host-prep.exe (one-time host ACL preparation).
#
# Besides the executor, the output directory gets MXC's license, the exact
# source it was built from (MXC-VERSION) and the crates statically linked into
# it with their declared licenses (MXC-THIRD-PARTY.md).
#
# Usage: build-mxc.ps1 -Arch x64|arm64 [-OutDir mxc-bin]
[CmdletBinding()]
param(
  [ValidateSet('x64', 'arm64')]
  [string]$Arch = 'x64',
  [string]$OutDir = 'mxc-bin'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# MXC main at c6f301d (2026-10-09): the v1.0.0 tag plus 20 commits, including
# microsoft/mxc#1406 (identity-less loopback proxy), which the engine's proxy
# mode needs. Request contract 1.0.0. Bump deliberately: the engine emits
# exact contract versions and is tested against this executor.
$MxcRepo = 'https://github.com/microsoft/mxc'
$MxcCommit = 'c6f301d53a1430c4c921a05c57af838f7392348f'

$target = if ($Arch -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
$src = Join-Path (Get-Location) 'mxc-src'

if (-not (Test-Path (Join-Path $src '.git'))) {
  git init --quiet $src
  if ($LASTEXITCODE) { throw 'git init failed' }
}
git -C $src fetch --quiet --depth 1 $MxcRepo $MxcCommit
if ($LASTEXITCODE) { throw "git fetch of $MxcCommit failed" }
git -C $src checkout --quiet --force FETCH_HEAD
if ($LASTEXITCODE) { throw 'git checkout failed' }
# A re-run in the same workspace must not build with files a previous
# checkout left behind (the cargo target directory is kept for speed).
git -C $src clean --quiet -fdx --exclude=src/target
if ($LASTEXITCODE) { throw 'git clean failed' }
$head = git -C $src rev-parse HEAD
if ($head -ne $MxcCommit) { throw "checked out $head, expected $MxcCommit" }

# src/rust-toolchain.toml pins the toolchain; rustup installs it on demand.
Push-Location (Join-Path $src 'src')
try {
  rustup target add $target
  if ($LASTEXITCODE) { throw "rustup target add $target failed" }
  cargo build --locked --release --target $target -p wxc
  if ($LASTEXITCODE) { throw 'cargo build failed' }
  $metadataJson = cargo metadata --format-version 1 --locked --filter-platform $target
  if ($LASTEXITCODE) { throw 'cargo metadata failed' }
} finally {
  Pop-Location
}

New-Item -ItemType Directory -Force $OutDir | Out-Null
$exe = Join-Path $src "src\target\$target\release\wxc-exec.exe"
Copy-Item $exe (Join-Path $OutDir 'wxc-exec.exe') -Force
Copy-Item (Join-Path $src 'LICENSE.md') (Join-Path $OutDir 'MXC-LICENSE.md') -Force
Set-Content -Path (Join-Path $OutDir 'MXC-VERSION') -Value "$MxcRepo@$MxcCommit" -NoNewline

# Third-party notice: every crate wxc depends on outside dev-dependencies,
# with the license its manifest declares.
$meta = $metadataJson | ConvertFrom-Json -Depth 100
$nodes = @{}
foreach ($n in $meta.resolve.nodes) { $nodes[$n.id] = $n }
$root = ($meta.packages | Where-Object { $_.name -eq 'wxc' } | Select-Object -First 1).id
if (-not $root) { throw 'package wxc not found in cargo metadata' }
$seen = @{}
$stack = [System.Collections.Generic.Stack[string]]::new()
$stack.Push($root)
while ($stack.Count -gt 0) {
  $id = $stack.Pop()
  if ($seen.ContainsKey($id)) { continue }
  $seen[$id] = $true
  foreach ($dep in $nodes[$id].deps) {
    if ($dep.dep_kinds | Where-Object { $_.kind -ne 'dev' }) { $stack.Push($dep.pkg) }
  }
}
$crates = $meta.packages | Where-Object { $seen.ContainsKey($_.id) -and $_.source } | Sort-Object name, version
$lines = @(
  '# Third-party crates in wxc-exec.exe',
  '',
  "wxc-exec.exe is built from $MxcRepo at $MxcCommit for $target. MXC's own",
  'license is in MXC-LICENSE.md. The crates below are compiled into the executable;',
  "each is listed with the license its manifest declares and its source repository.",
  '',
  '| Crate | Version | License | Repository |',
  '| --- | --- | --- | --- |'
)
foreach ($c in $crates) {
  $license = if ($c.license) { $c.license } elseif ($c.license_file) { "see $($c.license_file)" } else { 'unspecified' }
  $lines += "| $($c.name) | $($c.version) | $license | $($c.repository) |"
}
Set-Content -Path (Join-Path $OutDir 'MXC-THIRD-PARTY.md') -Value $lines
Get-ChildItem $OutDir | ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name }
