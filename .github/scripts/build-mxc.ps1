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
# Usage: build-mxc.ps1 -Arch x64|arm64 [-OutDir mxc-bin]
[CmdletBinding()]
param(
  [ValidateSet('x64', 'arm64')]
  [string]$Arch = 'x64',
  [string]$OutDir = 'mxc-bin'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# MXC 1.0.0, request contract 1.0.0 (2026-10-09). Bump deliberately: the engine
# emits exact contract versions and is tested against this executor.
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
$head = git -C $src rev-parse HEAD
if ($head -ne $MxcCommit) { throw "checked out $head, expected $MxcCommit" }

# src/rust-toolchain.toml pins the toolchain; rustup installs it on demand.
Push-Location (Join-Path $src 'src')
try {
  rustup target add $target
  if ($LASTEXITCODE) { throw "rustup target add $target failed" }
  cargo build --locked --release --target $target -p wxc
  if ($LASTEXITCODE) { throw 'cargo build failed' }
} finally {
  Pop-Location
}

New-Item -ItemType Directory -Force $OutDir | Out-Null
$exe = Join-Path $src "src\target\$target\release\wxc-exec.exe"
Copy-Item $exe (Join-Path $OutDir 'wxc-exec.exe') -Force
Copy-Item (Join-Path $src 'LICENSE.md') (Join-Path $OutDir 'MXC-LICENSE.md') -Force
Set-Content -Path (Join-Path $OutDir 'MXC-VERSION') -Value "$MxcRepo@$MxcCommit" -NoNewline
Get-ChildItem $OutDir | ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name }
