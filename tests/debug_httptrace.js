import { execSync, spawn } from 'node:child_process';
import { existsSync, writeFileSync, unlinkSync, copyFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('=== ENVIRONMENT INFO ===');
try {
  console.log('Kernel:', execSync('uname -a').toString().trim());
  const uid = process.getuid?.();
  console.log('User:', execSync('whoami').toString().trim(), 'UID:', uid);
  if (uid !== 0) {
    console.log('\n[!WARNING] running as non-root user (UID !== 0).');
    console.log('eBPF tracing requires sudo or CAP_BPF+CAP_PERFMON+CAP_SYS_RESOURCE capabilities.');
    console.log('Consider running: sudo node tests/debug_httptrace.js\n');
  }
  console.log('Capabilities:', execSync('capsh --print 2>/dev/null || echo "capsh not available"').toString().trim());
} catch (e) {
  console.error('Failed to get environment info:', e.message);
}

console.log('\n=== CRYPTO LIBRARIES ON SYSTEM ===');
const paths = [
  '/usr/lib/x86_64-linux-gnu/libssl.so*',
  '/usr/lib/aarch64-linux-gnu/libssl.so*',
  '/lib/x86_64-linux-gnu/libssl.so*',
  '/lib/aarch64-linux-gnu/libssl.so*',
  '/usr/lib64/libssl.so*',
  '/usr/lib/libssl.so*',
  '/lib/libssl.so*',
  '/usr/local/lib/libssl.so*',
  '/usr/local/lib64/libssl.so*',
  '/usr/lib/x86_64-linux-gnu/libgnutls.so*',
  '/usr/lib/aarch64-linux-gnu/libgnutls.so*',
  '/lib/x86_64-linux-gnu/libgnutls.so*',
  '/usr/lib64/libgnutls.so*',
  '/usr/lib/libgnutls.so*',
];

for (const pattern of paths) {
  try {
    const files = execSync(`ls -l ${pattern} 2>/dev/null`).toString().trim();
    if (files) {
      console.log(`${pattern}:\n${files}`);
    }
  } catch {}
}

// Check if curl is available and uses shared libssl
console.log('\n=== CURL INFO ===');
try {
  const curlPath = execSync('which curl 2>/dev/null').toString().trim();
  console.log('curl path:', curlPath);
  console.log('curl version:', execSync('curl --version 2>/dev/null | head -2').toString().trim());
  // Check if curl links against shared libssl
  try {
    const lddOut = execSync(`ldd ${curlPath} 2>/dev/null | grep -i ssl`).toString().trim();
    console.log('curl SSL deps:', lddOut || '(none — may be statically linked)');
  } catch {}
} catch {
  console.log('curl: not found');
}

console.log('\n=== TESTING SAFER-EXEC BINARY DIRECTLY ===');
const localBinary = join(__dirname, '..', 'go', 'bin', 'safer-exec-rt');
const systemBinary = '/usr/local/bin/safer-exec-rt';

if (process.getuid?.() === 0 && existsSync(localBinary)) {
  try {
    copyFileSync(localBinary, systemBinary);
    console.log(`Successfully bootstrapped local binary to ${systemBinary}`);
  } catch (err) {
    console.warn(`Warning: failed to bootstrap local binary to ${systemBinary}:`, err.message);
  }
}

const binaryToUse = existsSync(systemBinary) ? systemBinary : localBinary;

console.log(`Using binary: ${binaryToUse}`);
if (!existsSync(binaryToUse)) {
  console.error(`ERROR: Binary does not exist at ${binaryToUse}. Please compile it first.`);
  process.exit(1);
}

// Helper: run safer-exec with a given config and return { stdout, stderr, code }
function runSaferExec(config, useStrace = false) {
  return new Promise((resolve) => {
    let cmd = binaryToUse;
    let args = [];
    if (useStrace) {
      cmd = 'strace';
      args = ['-f', '-s', '512', binaryToUse];
    }
    const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('close', (code) => resolve({ stdout, stderr, code }));
    child.stdin.write(JSON.stringify(config));
    child.stdin.end();
  });
}

// Helper: analyse events from stderr
function analyseEvents(stderr) {
  let hasCryptoCipher = false;
  let hasCryptoLib = false;
  let hasHttpReq = false;
  let cipherName = '';
  let tlsVersion = '';
  let cryptoLibrary = '';

  for (const line of stderr.split('\n')) {
    if (line.startsWith('{') && line.endsWith('}')) {
      try {
        const ev = JSON.parse(line);
        if (ev.type === 'crypto-cipher') { hasCryptoCipher = true; cipherName = cipherName || ev.name; }
        if (ev.type === 'crypto-library') { hasCryptoLib = true; cryptoLibrary = cryptoLibrary || ev.name; }
        if (ev.type === 'http-request') {
          hasHttpReq = true;
          if (ev.cipher && !cipherName) cipherName = ev.cipher;
          if (ev.tlsVersion && !tlsVersion) tlsVersion = ev.tlsVersion;
          if (ev.cryptoLibrary && !cryptoLibrary) cryptoLibrary = ev.cryptoLibrary;
        }
      } catch {}
    }
  }
  return { hasCryptoCipher, hasCryptoLib, hasHttpReq, cipherName, tlsVersion, cryptoLibrary };
}

// ── Test 1: curl (uses shared libssl, calls SSL_get_current_cipher automatically) ──
const curlPath = (() => { try { return execSync('which curl 2>/dev/null').toString().trim(); } catch { return ''; } })();

if (curlPath) {
  console.log('\n\n=== TEST 1: curl (shared libssl) ===');

  const curlReadPaths = [
    curlPath,
    '/lib', '/lib64', '/usr/lib', '/usr/lib64',
    '/etc/resolv.conf', '/etc/hosts', '/etc/ssl/certs',
    '/usr/share/ca-certificates', '/etc/ca-certificates',
    '/run/systemd/resolve/stub-resolv.conf',
    '/etc/pki/tls/certs',
    '/opt/orbstack-guest',
  ];

  const curlConfig = {
    cmd: curlPath,
    args: ['-s', '-o', '/dev/null', '-w', '%{http_code}', 'https://registry.npmjs.org/'],
    traceHTTPURLs: true,
    traceCrypto: true,
    cryptoProbeMode: 'all',
    enableAudit: true,
    allowHosts: ['registry.npmjs.org'],
    readPaths: curlReadPaths,
  };

  console.log('\nConfig payload being sent on stdin:');
  console.log(JSON.stringify(curlConfig, null, 2));

  const curlResult = await runSaferExec(curlConfig);
  console.log(`\nsafer-exec exited with code: ${curlResult.code}`);
  console.log('\n=== STDOUT ===');
  console.log(curlResult.stdout || '(empty)');
  console.log('\n=== STDERR ===');
  console.log(curlResult.stderr || '(empty)');

  if (curlResult.code !== 0) {
    console.log('\n=== RUNNING WITH STRACE FOR DIAGNOSTICS (curl) ===');
    const straceRes = await runSaferExec(curlConfig, true);
    console.log('=== STRACE OUTPUT ===');
    console.log(straceRes.stderr);
  }

  console.log('\n=== ANALYZED EVENTS (curl) ===');
  const curlAnalysis = analyseEvents(curlResult.stderr);
  console.log(`- Captured http-request: ${curlAnalysis.hasHttpReq ? 'YES' : 'NO'}`);
  console.log(`- Captured crypto-library: ${curlAnalysis.hasCryptoLib ? 'YES' : 'NO'} ${curlAnalysis.cryptoLibrary ? `(${curlAnalysis.cryptoLibrary})` : ''}`);
  console.log(`- Captured crypto-cipher: ${curlAnalysis.hasCryptoCipher ? 'YES' : 'NO'} ${curlAnalysis.cipherName ? `(${curlAnalysis.cipherName})` : ''}`);
  console.log(`- TLS version: ${curlAnalysis.tlsVersion || '(not captured)'}`);
} else {
  console.log('\n\n=== TEST 1: curl not available, skipping ===');
}

// ── Test 2: Node.js with getCipher() call (verifies correlation logic) ──
console.log('\n\n=== TEST 2: Node.js with explicit getCipher() call ===');

const tempScriptPath = join('/tmp', `debug_req_${Date.now()}.js`);
const tempScriptContent = `
import https from 'node:https';
console.log("Starting HTTPS request inside sandbox...");
const req = https.get('https://registry.npmjs.org/', (res) => {
  console.log("HTTPS Response Status:", res.statusCode);
  res.resume();
  res.on('end', () => {
    console.log("HTTPS request finished.");
    process.exit(0);
  });
});
req.on('socket', (socket) => {
  socket.on('secureConnect', () => {
    // Explicitly call getCipher() to trigger SSL_get_current_cipher
    const cipher = socket.getCipher();
    console.log("Cipher (from getCipher):", JSON.stringify(cipher));
  });
});
req.on('error', (err) => {
  console.error("HTTPS Request Error:", err.message);
  process.exit(1);
});
`;

writeFileSync(tempScriptPath, tempScriptContent);

const nodeConfig = {
  cmd: process.execPath,
  args: [tempScriptPath],
  traceHTTPURLs: true,
  traceCrypto: true,
  cryptoProbeMode: 'all',
  enableAudit: true,
  allowHosts: ['registry.npmjs.org'],
  readPaths: [
    process.execPath,
    tempScriptPath,
    '/lib', '/lib64', '/usr/lib', '/usr/lib64',
    '/etc/resolv.conf', '/etc/hosts', '/etc/ssl/certs',
    '/usr/share/ca-certificates', '/etc/ca-certificates',
    '/run/systemd/resolve/stub-resolv.conf',
    '/opt/orbstack-guest',
  ],
};

console.log('\nConfig payload being sent on stdin:');
console.log(JSON.stringify(nodeConfig, null, 2));

const nodeResult = await runSaferExec(nodeConfig);
console.log(`\nsafer-exec exited with code: ${nodeResult.code}`);
console.log('\n=== STDOUT ===');
console.log(nodeResult.stdout || '(empty)');
console.log('\n=== STDERR ===');
console.log(nodeResult.stderr || '(empty)');

if (nodeResult.code !== 0) {
  console.log('\n=== RUNNING WITH STRACE FOR DIAGNOSTICS (node) ===');
  const straceRes = await runSaferExec(nodeConfig, true);
  console.log('=== STRACE OUTPUT ===');
  console.log(straceRes.stderr);
}

console.log('\n=== ANALYZED EVENTS (node + getCipher) ===');
const nodeAnalysis = analyseEvents(nodeResult.stderr);
console.log(`- Captured http-request: ${nodeAnalysis.hasHttpReq ? 'YES' : 'NO'}`);
console.log(`- Captured crypto-library: ${nodeAnalysis.hasCryptoLib ? 'YES' : 'NO'} ${nodeAnalysis.cryptoLibrary ? `(${nodeAnalysis.cryptoLibrary})` : ''}`);
console.log(`- Captured crypto-cipher: ${nodeAnalysis.hasCryptoCipher ? 'YES' : 'NO'} ${nodeAnalysis.cipherName ? `(${nodeAnalysis.cipherName})` : ''}`);
console.log(`- TLS version: ${nodeAnalysis.tlsVersion || '(not captured)'}`);

// Symbol diagnostics on system libssl.so
console.log('\n=== SYMBOL DIAGNOSTICS (libssl.so) ===');
const libsslMatches = [];
for (const pattern of paths) {
  if (pattern.includes('libssl.so*')) {
    try {
      const resolved = execSync(`ls ${pattern} 2>/dev/null`).toString().trim().split('\n');
      for (const file of resolved) {
        if (file && !file.endsWith('.a') && !libsslMatches.includes(file)) {
          libsslMatches.push(file);
        }
      }
    } catch {}
  }
}

for (const lib of libsslMatches) {
  try {
    const realLib = execSync(`readlink -f ${lib}`).toString().trim();
    console.log(`Library: ${lib} -> ${realLib}`);
    for (const sym of ['SSL_write', 'SSL_get_current_cipher', 'SSL_CIPHER_get_name']) {
      let hasSym = false;
      try {
        const out = execSync(`objdump -T ${realLib} 2>/dev/null | grep -w ${sym} || readelf -s ${realLib} 2>/dev/null | grep -w ${sym}`).toString().trim();
        if (out) hasSym = true;
      } catch {}
      console.log(`  - Symbol ${sym.padEnd(24)}: ${hasSym ? 'FOUND' : 'NOT FOUND'}`);
    }
  } catch (e) {
    console.log(`  Error inspecting ${lib}: ${e.message}`);
  }
}

try {
  unlinkSync(tempScriptPath);
} catch {}
