/**
 * DNS resolution utilities for converting hostnames to IP addresses.
 *
 * The sandbox engines (macOS Seatbelt, Linux namespaces) filter by
 * IP address, not hostname. This module resolves hostnames ahead of
 * time so the sandbox can enforce network policies correctly.
 *
 * @module net
 */

import { promises as dns } from 'node:dns';

/**
 * Resolve a hostname to its IPv4 and IPv6 addresses.
 *
 * Performs both A (IPv4) and AAAA (IPv6) lookups. Returns an empty
 * array if the hostname resolves to nothing.
 *
 * @param {string} hostname - The hostname to resolve
 * @param {Object} [options] - DNS resolution options
 * @param {number} [options.timeout=5000] - Maximum time in ms to wait for resolution
 * @param {boolean} [options.includeIpv6=true] - Whether to include IPv6 addresses
 * @returns {Promise<string[]>} Array of resolved IP addresses
 * @throws {Error} If the hostname cannot be resolved within the timeout
 *
 * @example
 * const ips = await resolveHost('registry.npmjs.org');
 * // => ['100.24.50.13', '2606:4700::6812:fda', ...]
 */
export async function resolveHost(hostname, options = {}) {
  const { timeout = 5000, includeIpv6 = true } = options;

  if (typeof hostname !== 'string' || hostname.trim() === '') {
    throw new TypeError('hostname must be a non-empty string');
  }

  const results = [];
  const retries = 3;

  const runWithRetry = async (fn) => {
    let lastErr;
    for (let i = 0; i < retries; i++) {
      try {
        return await fn();
      } catch (err) {
        lastErr = err;
        if (i < retries - 1) {
          await new Promise((resolve) => setTimeout(resolve, 500));
        }
      }
    }
    throw lastErr;
  };

  // Resolve IPv4 addresses
  try {
    const ipv4Addresses = await runWithRetry(() => dns.resolve4(hostname));
    results.push(...ipv4Addresses);
  } catch {
    // Host might only have IPv6 or resolve failed
  }

  // Resolve IPv6 addresses
  if (includeIpv6) {
    try {
      const ipv6Addresses = await runWithRetry(() => dns.resolve6(hostname));
      results.push(...ipv6Addresses);
    } catch {
      // Host might only have IPv4 or resolve failed
    }
  }

  // Deduplicate results
  return [...new Set(results)];
}

/**
 * Resolve multiple hostnames to their IP addresses.
 *
 * Resolves all hostnames in parallel. If any hostname fails to resolve,
 * the error is collected but doesn't prevent other hostnames from resolving.
 *
 * @param {string[]} hostnames - Array of hostnames to resolve
 * @param {Object} [options] - Options passed to resolveHost()
 * @returns {Promise<{ips: string[], failures: Array<{host: string, error: string}>}>}
 *          Resolved IPs and any failures
 *
 * @example
 * const { ips, failures } = await resolveHosts([
 *   'registry.npmjs.org',
 *   'registry.yarnpkg.com',
 *   'invalid-host.example'
 * ]);
 * // => { ips: ['100.24.50.13', ...], failures: [{host: 'invalid-host.example', error: '...'}] }
 */
export async function resolveHosts(hostnames, options = {}) {
  const ips = new Set();
  const failures = [];

  const promises = hostnames.map(async (hostname) => {
    try {
      const resolved = await resolveHost(hostname, options);
      for (const ip of resolved) {
        ips.add(ip);
      }
    } catch (error) {
      failures.push({
        host: hostname,
        error: error.message || String(error),
      });
    }
  });

  await Promise.all(promises);

  return {
    ips: [...ips],
    failures,
  };
}
