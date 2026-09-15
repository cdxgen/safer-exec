//go:build darwin

package main

import (
	"strings"
	"testing"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// Regression coverage for the unified-log deny lines macOS emits for
// sandboxed processes. Observed formats (macOS 26, compact log style):
//
//	Sandbox: cat(40289) deny(1) file-read-data /Users/x/secret
//	Sandbox: curl(40642) deny(1) network-outbound remote:*:443
//	Sandbox: sh(39951) deny(1) sysctl-read kern.bootargs        (skipped as noise)
func TestParseSandboxLogLine(t *testing.T) {
	cases := []struct {
		line string
		want *config.DryRunEvent
	}{
		{
			line: `2026-09-14 23:29:46.056 E  kernel[0:180923] (Sandbox) Sandbox: cat(40289) deny(1) file-read-data /Users/prabhu/safer-exec-roadmap/README.md`,
			want: &config.DryRunEvent{Type: "file-read", Path: "/Users/prabhu/safer-exec-roadmap/README.md"},
		},
		{
			line: `kernel[0:17c2fb] (Sandbox) Sandbox: curl(40642) deny(1) network-outbound remote:*:443`,
			want: &config.DryRunEvent{Type: "network-outbound", Target: "*", Port: 443},
		},
		{
			line: `kernel[0:17c5bb] (Sandbox) Sandbox: curl(40541) deny(1) network-outbound /private/var/run/mDNSResponder`,
			want: &config.DryRunEvent{Type: "network-outbound", Target: "/private/var/run/mDNSResponder"},
		},
		{
			line: `kernel[0:17e495] (Sandbox) Sandbox: bash(40288) deny(1) file-write-create /private/tmp/sbx-dryrun-out.txt`,
			want: &config.DryRunEvent{Type: "file-write", Path: "/private/tmp/sbx-dryrun-out.txt"},
		},
		{
			line: `kernel[0:1] (Sandbox) Sandbox: make(1) deny(1) file-read-metadata /Users/x/proj`,
			want: &config.DryRunEvent{Type: "file-metadata", Path: "/Users/x/proj"},
		},
		{
			line: `kernel[0:1] (Sandbox) Sandbox: sh(1) deny(1) sysctl-read kern.bootargs`,
			want: nil,
		},
		{
			line: `kernel[0:1] (Sandbox) Sandbox: app(1) deny(1) mach-lookup com.apple.cfprefsd`,
			want: nil,
		},
		{
			line: `kernel[0:1] (Sandbox) 2 duplicate reports for Sandbox: app(1) deny(1) file-read-data /x`,
			want: nil, // duplicate aggregation lines must not double-count
		},
	}

	for _, tc := range cases {
		m := sandboxEventLine.FindStringSubmatch(tc.line)
		if m == nil {
			if tc.want != nil {
				t.Errorf("line did not match: %q", tc.line)
			}
			continue
		}
		if tc.want == nil {
			// For noise/duplicate lines the regex may match (duplicates share
			// the suffix shape only when the count leads); assert the mapping drops them.
			if ev := sandboxOpToEvent(m[4], m[5]); ev != nil && strings.Contains(tc.line, "sysctl") {
				t.Errorf("noise op %q must be dropped, got %+v", m[4], ev)
			}
			continue
		}
		got := sandboxOpToEvent(m[4], m[5])
		if got == nil {
			t.Errorf("sandboxOpToEvent returned nil for %q", tc.line)
			continue
		}
		if got.Type != tc.want.Type || got.Path != tc.want.Path || got.Target != tc.want.Target || got.Port != tc.want.Port {
			t.Errorf("line %q\n got %+v\nwant %+v", tc.line, got, tc.want)
		}
	}
}

func TestSandboxEventLineDuplicateReportsDoNotMatch(t *testing.T) {
	line := `2026-09-14 23:24:53.717742+0100 kernel[0:17bd4e] (Sandbox) 1 duplicate report for Sandbox: ContextStoreAgent(719) allow file-read-data /Applications/ZCode.app`
	if _, ev := sandboxEventFromLine(line); ev != nil {
		t.Errorf("duplicate-report lines must not parse as events (they would double-count): %q -> %+v", line, ev)
	}
}

func TestBuildDryRunProfileAllowsBootstrap(t *testing.T) {
	profile := buildDryRunProfile(config.ExecConfig{Cmd: "/bin/sh"}, "/bin/sh")
	// Without the root read + metadata allows, the target aborts on its first
	// denied bootstrap lookup and the report degenerates to bootstrap noise.
	if !strings.Contains(profile, `(allow file-read-data (literal "/"))`) {
		t.Errorf("dry-run profile missing root read allow\n%s", profile)
	}
	if !strings.Contains(profile, "(allow file-read-metadata)") {
		t.Errorf("dry-run profile missing metadata allow\n%s", profile)
	}
}

func TestSeatbeltProfileProxyEgressRules(t *testing.T) {
	profile := buildSeatbeltProfile(config.ExecConfig{Cmd: "/bin/true", ProxyEgress: true}, 8899)
	if !strings.Contains(profile, `(allow network-outbound (remote ip "localhost:8899"))`) {
		t.Errorf("proxy profile missing loopback proxy-port rule\n%s", profile)
	}
	if strings.Contains(profile, "(allow network-outbound)\n") {
		t.Errorf("proxy profile must not fall through to unrestricted egress\n%s", profile)
	}
	// mDNSResponder keepalive for local resolution
	if !strings.Contains(profile, `/private/var/run/mDNSResponder`) {
		t.Errorf("proxy profile missing DNS resolver rule\n%s", profile)
	}
}
