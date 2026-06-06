/**
 * SSL certificate path helpers for all ecosystem policies.
 *
 * @module sslhelper
 */

export const isMac = process.platform === 'darwin';
export const isWin = process.platform === 'win32';

/**
 * Return platform-specific SSL certificate paths.
 *
 * @returns {string[]} SSL certificate paths for the current platform
 */
export function getSslPaths() {
  if (isMac) {
    return [
      '/opt/homebrew/etc/openssl@3/certs',
      '/opt/homebrew/etc/openssl@1.1/certs',
      '/usr/local/etc/openssl@3/certs',
      '/usr/local/etc/openssl@1.1/certs', // Added legacy fallback
      '/etc/ssl/certs',
    ];
  }
  if (isWin) {
    // Windows primarily uses the OS trust store via CryptoAPI/SChannel.
    // Explicit file reads for certs are usually unnecessary.
    return [];
  }
  return [
    '/etc/ssl/certs',
    '/etc/pki/tls/certs',
    '/usr/share/ca-certificates',
    '/etc/ca-certificates' // Added for Debian/Ubuntu environments
  ];
}