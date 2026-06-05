/**
 * SSL certificate path helpers for all ecosystem policies.
 *
 * @module sslhelper
 */

export const isMac = process.platform === 'darwin';

/**
 * Return platform-specific SSL certificate paths.
 *
 * @returns {string[]} SSL certificate paths for the current platform
 */
export function getSslPaths() {
  if (isMac) {
    return ["/opt/homebrew/etc/openssl@3/certs", "/opt/homebrew/etc/openssl@1.1/certs", '/usr/local/etc/openssl@3/certs', '/etc/ssl/certs'];
  }
  return ['/etc/ssl/certs', '/etc/pki/tls/certs', '/usr/share/ca-certificates'];
}
