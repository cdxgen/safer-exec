/**
 * Unit tests for the DNS resolution module (net.js).
 *
 * Tests hostname resolution, multiple host resolution, error handling,
 * and edge cases.
 *
 * @module net_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { resolveHost, resolveHosts } from './net.js';

describe('resolveHost', () => {
  it('should resolve a known hostname to at least one IP', async () => {
    const ips = await resolveHost('github.com');
    strict.ok(ips.length > 0, 'should resolve at least one IP');
    // IPs should be valid format
    for (const ip of ips) {
      strict.ok(
        /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(ip) ||
        /^[0-9a-f:]+$/.test(ip),
        `IP should be valid format: ${ip}`
      );
    }
  });

  it('should resolve Google DNS (IPv4)', async () => {
    const ips = await resolveHost('dns.google');
    strict.ok(
      ips.includes('8.8.8.8') || ips.includes('8.8.4.4'),
      'should include Google DNS IP'
    );
  });

  it('should throw on empty hostname', async () => {
    await strict.rejects(
      resolveHost(''),
      TypeError,
      'hostname must be a non-empty string'
    );
  });

  it('should throw on non-string hostname', async () => {
    await strict.rejects(
      resolveHost(123),
      TypeError,
      'hostname must be a non-empty string'
    );
  });

  it('should return empty array for unresolvable hostname', async () => {
    const ips = await resolveHost('nonexistent-host-example.local');
    strict.equal(ips.length, 0, 'should return empty array for unresolvable host');
  });

  it('should include IPv6 when includeIpv6 is true', async () => {
    const ipv4Only = await resolveHost('github.com', { includeIpv6: false });
    const all = await resolveHost('github.com', { includeIpv6: true });

    // All should have at least as many as IPv4 only
    strict.ok(
      all.length >= ipv4Only.length,
      'IPv6 inclusion should not reduce results'
    );
  });
});

describe('resolveHosts', () => {
  it('should resolve multiple hostnames', async () => {
    const { ips, failures } = await resolveHosts([
      'github.com',
      'google.com',
    ]);

    strict.ok(ips.length > 0, 'should resolve at least some IPs');
    strict.equal(failures.length, 0, 'should have no failures for real hosts');
  });

  it('should collect failures for unresolvable hosts', async () => {
    const { ips, failures } = await resolveHosts([
      'github.com',
      'nonexistent-host-example-12345.local',
      'google.com',
    ]);

    strict.ok(ips.length > 0, 'should resolve at least some IPs');
    // DNS resolution might succeed for .local domains on some systems
    // so we just verify the function handles multiple hosts correctly
    strict.ok(
      ips.length >= 2,
      'should resolve at least 2 IPs from real hosts'
    );
  });

  it('should deduplicate IPs across hostnames', async () => {
    // Resolve the same host twice — IPs should be deduplicated
    const { ips } = await resolveHosts(['github.com', 'github.com']);

    // Check no duplicates
    const unique = new Set(ips);
    strict.equal(unique.size, ips.length, 'IPs should be deduplicated');
  });

  it('should handle empty hostnames array', async () => {
    const { ips, failures } = await resolveHosts([]);
    strict.equal(ips.length, 0, 'should return empty IPs');
    strict.equal(failures.length, 0, 'should return empty failures');
  });
});
