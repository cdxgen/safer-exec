//go:build darwin

package main

import (
	"strings"
	"testing"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// Seatbelt's (remote ip ...) filter only accepts "*" or "localhost" as the
// host, so egress can be confined by port but not pinned to a specific IP.
// These tests assert the honest, valid behavior: when host pinning is
// requested we restrict to the requested ports (never fall through to an
// unrestricted allow) and emit only profiles sandbox-exec will accept.

func TestSeatbelt_HostPinningRestrictsToPorts(t *testing.T) {
	profile := buildSeatbeltProfile(config.ExecConfig{
		Cmd:        "/bin/true",
		AllowIPs:   []string{"1.2.3.4"},
		AllowPorts: []int{443},
	})
	if !strings.Contains(profile, `(allow network-outbound (remote ip "*:443"))`) {
		t.Errorf("profile missing port-confined egress rule\n%s", profile)
	}
	// Seatbelt cannot pin IPs, so no literal-IP rule must be emitted (it would be
	// rejected by sandbox-exec), and egress must not fall through to allow-all.
	if strings.Contains(profile, "1.2.3.4") {
		t.Errorf("profile emitted an unsupported literal-IP rule\n%s", profile)
	}
	if strings.Contains(profile, "(allow network-outbound)\n") {
		t.Errorf("profile fell through to unrestricted egress despite host pinning\n%s", profile)
	}
}

func TestSeatbelt_HostPinningWithoutPortsDefaultsToWebPorts(t *testing.T) {
	profile := buildSeatbeltProfile(config.ExecConfig{
		Cmd:      "/bin/true",
		AllowIPs: []string{"1.2.3.4"},
	})
	for _, want := range []string{
		`(allow network-outbound (remote ip "*:80"))`,
		`(allow network-outbound (remote ip "*:443"))`,
	} {
		if !strings.Contains(profile, want) {
			t.Errorf("profile missing default web-port rule %q\n%s", want, profile)
		}
	}
	if strings.Contains(profile, "(allow network-outbound)\n") {
		t.Errorf("profile fell through to unrestricted egress\n%s", profile)
	}
}

func TestSeatbelt_PortWildcardFallbackWithoutIPs(t *testing.T) {
	profile := buildSeatbeltProfile(config.ExecConfig{
		Cmd:        "/bin/true",
		AllowPorts: []int{443},
	})
	if !strings.Contains(profile, `(allow network-outbound (remote ip "*:443"))`) {
		t.Errorf("profile missing port rule when no IPs pinned\n%s", profile)
	}
}

func TestSeatbelt_DisableNetworkRestrictsToPorts(t *testing.T) {
	profile := buildSeatbeltProfile(config.ExecConfig{
		Cmd:            "/bin/true",
		DisableNetwork: true,
		AllowIPs:       []string{"10.0.0.5"},
		AllowPorts:     []int{443},
	})
	if !strings.Contains(profile, "(deny network-outbound)") {
		t.Errorf("disableNetwork profile missing deny rule\n%s", profile)
	}
	if !strings.Contains(profile, `(allow network-outbound (remote ip "*:443"))`) {
		t.Errorf("disableNetwork profile missing port re-allow rule\n%s", profile)
	}
}

func TestSeatbelt_DeniesCredentialStores(t *testing.T) {
	profile := buildSeatbeltProfile(config.ExecConfig{Cmd: "/bin/true"})
	for _, p := range []string{"/Library/Keychains", "/private/var/db/dslocal"} {
		want := `(deny file-read* (subpath "` + p + `"))`
		if !strings.Contains(profile, want) {
			t.Errorf("profile missing credential-store deny %q\n%s", want, profile)
		}
	}
}

func TestSeatbelt_ProfileValidForPinnedHosts(t *testing.T) {
	// Regression guard: a profile generated when host pinning is requested must
	// not contain any literal-IP remote rule, which sandbox-exec rejects with
	// "host must be * or localhost".
	profile := buildSeatbeltProfile(config.ExecConfig{
		Cmd:        "/bin/true",
		AllowIPs:   []string{"93.184.216.34", "2606:4700::1111"},
		AllowPorts: []int{80},
	})
	for _, line := range strings.Split(profile, "\n") {
		if strings.Contains(line, "network-outbound") && strings.Contains(line, "remote ip") {
			if !strings.Contains(line, `"*:`) && !strings.Contains(line, `"localhost:`) {
				t.Errorf("profile contains a non-wildcard remote ip rule sandbox-exec would reject: %q", line)
			}
		}
	}
}
