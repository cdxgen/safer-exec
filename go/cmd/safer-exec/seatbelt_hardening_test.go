//go:build darwin

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// indexOf returns the byte offset of sub in s, or -1. Used to assert ordering
// (last-match-wins) of allow/deny rules in generated Seatbelt profiles.
func indexOf(s, sub string) int { return strings.Index(s, sub) }

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
	}, 0)
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
	}, 0)
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
	}, 0)
	if !strings.Contains(profile, `(allow network-outbound (remote ip "*:443"))`) {
		t.Errorf("profile missing port rule when no IPs pinned\n%s", profile)
	}
}

func TestSeatbelt_DisableNetworkIsAbsolute(t *testing.T) {
	profile := buildSeatbeltProfile(config.ExecConfig{
		Cmd:            "/bin/true",
		DisableNetwork: true,
		AllowIPs:       []string{"10.0.0.5"},
		AllowPorts:     []int{443},
	}, 0)
	if !strings.Contains(profile, "(deny network-outbound)") {
		t.Errorf("disableNetwork profile missing deny rule\n%s", profile)
	}
	// Seatbelt cannot pin remote IPs, so re-allowing the requested ports under
	// disableNetwork would open those ports to every host on the internet —
	// the opposite of disabling the network. Nothing but loopback (when
	// explicitly allowed) may be re-allowed.
	if strings.Contains(profile, `(allow network-outbound (remote ip "*`) {
		t.Errorf("disableNetwork must not re-allow remote egress\n%s", profile)
	}
}

func TestSeatbelt_DeniesCredentialStores(t *testing.T) {
	profile := buildSeatbeltProfile(config.ExecConfig{Cmd: "/bin/true"}, 0)
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
	}, 0)
	for _, line := range strings.Split(profile, "\n") {
		if strings.Contains(line, "network-outbound") && strings.Contains(line, "remote ip") {
			if !strings.Contains(line, `"*:`) && !strings.Contains(line, `"localhost:`) {
				t.Errorf("profile contains a non-wildcard remote ip rule sandbox-exec would reject: %q", line)
			}
		}
	}
}

func TestSeatbelt_BlockInterpretersExecDenies(t *testing.T) {
	profile := buildSeatbeltProfile(config.ExecConfig{
		Cmd:               "/bin/true",
		BlockInterpreters: true,
	}, 0)
	want := []string{
		`(deny process-exec (literal "/usr/bin/tclsh"))`,
		`(deny process-exec (literal "/usr/bin/perl"))`,
		`(deny process-exec (literal "/usr/bin/python3"))`,
		`(deny process-exec (literal "/usr/bin/symbols"))`, // SamplingTools / task_for_pid
		`(deny process-exec (literal "/usr/bin/vmmap"))`,
		`(deny process-exec (subpath "/System/Library/Frameworks/Tcl.framework"))`,
		`(deny process-exec (subpath "/System/Library/Frameworks/AudioToolbox.framework/XPCServices"))`,
	}
	for _, w := range want {
		if !strings.Contains(profile, w) {
			t.Errorf("profile missing interpreter exec deny %q\n%s", w, profile)
		}
	}
}

func TestSeatbelt_BlockInterpretersReadDeniesAfterSystemAllow(t *testing.T) {
	profile := buildSeatbeltProfile(config.ExecConfig{
		Cmd:               "/bin/true",
		BlockInterpreters: true,
	}, 0)
	systemAllow := indexOf(profile, `(allow file-read* (subpath "/System"))`)
	ffidlDeny := indexOf(profile, `(deny file-read* (subpath "/System/Library/Tcl"))`)
	if systemAllow < 0 || ffidlDeny < 0 {
		t.Fatalf("expected both /System allow and Ffidl deny in profile\n%s", profile)
	}
	if ffidlDeny < systemAllow {
		t.Errorf("Ffidl read deny (%d) must come after /System allow (%d) for last-match-wins", ffidlDeny, systemAllow)
	}
}

func TestSeatbelt_BlockInterpretersSelfCmdGuard(t *testing.T) {
	// Deliberately running perl must not deny perl's own exec, while other
	// interpreters stay blocked.
	profile := buildSeatbeltProfile(config.ExecConfig{
		Cmd:               "/usr/bin/perl",
		BlockInterpreters: true,
	}, 0)
	if strings.Contains(profile, `(deny process-exec (literal "/usr/bin/perl"))`) {
		t.Errorf("self-cmd guard failed: perl denied its own exec\n%s", profile)
	}
	if !strings.Contains(profile, `(deny process-exec (literal "/usr/bin/tclsh"))`) {
		t.Errorf("other interpreters should still be denied\n%s", profile)
	}
}

func TestSeatbelt_DenyPersistenceWrites(t *testing.T) {
	t.Setenv("HOME", "/Users/tester")
	profile := buildSeatbeltProfile(config.ExecConfig{
		Cmd:                   "/bin/true",
		DenyPersistenceWrites: true,
	}, 0)
	want := []string{
		`(deny file-write* (subpath "/Library/LaunchAgents"))`,
		`(deny file-write* (subpath "/Library/LaunchDaemons"))`,
		`(deny file-write* (subpath "/usr/local/bin"))`,
		`(deny file-write* (subpath "/Users/tester/Library/LaunchAgents"))`,
		`(deny file-write* (subpath "/Users/tester/Library/Audio/MIDI Drivers"))`,
	}
	for _, w := range want {
		if !strings.Contains(profile, w) {
			t.Errorf("profile missing persistence write deny %q\n%s", w, profile)
		}
	}
}

func TestSeatbelt_DenyPersistenceWritesOptOut(t *testing.T) {
	// A path explicitly granted via WritePaths is exempt from the deny.
	profile := buildSeatbeltProfile(config.ExecConfig{
		Cmd:                   "/bin/true",
		DenyPersistenceWrites: true,
		WritePaths:            []string{"/usr/local/bin"},
	}, 0)
	if strings.Contains(profile, `(deny file-write* (subpath "/usr/local/bin"))`) {
		t.Errorf("explicitly-granted write path should not be denied\n%s", profile)
	}
	if !strings.Contains(profile, `(deny file-write* (subpath "/Library/LaunchAgents"))`) {
		t.Errorf("other persistence paths should still be denied\n%s", profile)
	}
}

func TestSeatbelt_WritableDylibDeny(t *testing.T) {
	profile := buildSeatbeltProfile(config.ExecConfig{
		Cmd:               "/bin/true",
		BlockInterpreters: true,
		WritePaths:        []string{"/work/build"},
	}, 0)
	// The deny must be anchored to the tree prefix AND the .dylib suffix in
	// a single regex: on current macOS, combining (subpath X) with (regex Y)
	// applies the regex system-wide, which would block loading every
	// non-cached dylib on the host (dotnet, Homebrew, ...).
	for _, w := range []string{
		`(deny file-read* (regex #"^/tmp/.*\.dylib$"))`,
		`(deny file-read* (regex #"^/work/build/.*\.dylib$"))`,
	} {
		if !strings.Contains(profile, w) {
			t.Errorf("profile missing anchored writable-dylib deny %q\n%s", w, profile)
		}
	}
	// The unanchored form must never appear — it is the system-wide bug.
	if strings.Contains(profile, `(regex #"\.dylib$")`) {
		t.Errorf("profile uses unanchored dylib regex (matches every .dylib on the host)\n%s", profile)
	}
}

func TestSeatbelt_WritableDylibDenyOptOut(t *testing.T) {
	profile := buildSeatbeltProfile(config.ExecConfig{
		Cmd:                    "/bin/true",
		BlockInterpreters:      true,
		AllowWritableDylibLoad: true,
		WritePaths:             []string{"/work/build"},
	}, 0)
	if strings.Contains(profile, `(regex #"\.dylib$")`) {
		t.Errorf("AllowWritableDylibLoad should suppress dylib read denies\n%s", profile)
	}
}

// TestSeatbelt_HardenedProfileValidates is a regression guard: the full set of
// hardening rules must produce a profile sandbox-exec accepts and enforces. We
// run a trivial allowed command under it; a malformed profile makes
// sandbox-exec exit before the command runs.
func TestSeatbelt_HardenedProfileValidates(t *testing.T) {
	sandboxPath, err := exec.LookPath("sandbox-exec")
	if err != nil {
		t.Skip("sandbox-exec not available")
	}
	profile := buildSeatbeltProfile(config.ExecConfig{
		Cmd:                   "/usr/bin/true",
		BlockInterpreters:     true,
		DenyPersistenceWrites: true,
		WritePaths:            []string{"/work/build"},
		AllowPorts:            []int{443},
	}, 0)
	tmp, err := os.CreateTemp("", "safer-exec-test-*.sb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(profile); err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	cmd := exec.Command(sandboxPath, "-f", tmp.Name(), "/usr/bin/true")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("sandbox-exec rejected/failed hardened profile: %v\n%s\n---profile---\n%s", err, out, profile)
	}
}

// securityd (the keychain endpoint) and the user-database services must not
// be reachable from a baseline sandbox: a build script that can talk to
// com.apple.SecurityServer can ask an unlocked login keychain for items whose
// ACL does not force a prompt. Certificate validation goes through trustd,
// which stays in the baseline.
func TestSeatbelt_SecurityServicesAreOptIn(t *testing.T) {
	base := buildSeatbeltProfile(config.ExecConfig{Cmd: "/bin/true"}, 0)
	for _, forbidden := range []string{
		"com.apple.SecurityServer",
		"com.apple.system.opendirectoryd",
		"com.apple.memberd",
	} {
		if strings.Contains(base, forbidden) {
			t.Errorf("baseline profile must not grant mach-lookup to %s\n%s", forbidden, base)
		}
	}
	// Trust evaluation must still work without it.
	if !strings.Contains(base, `(allow mach-lookup (global-name "com.apple.trustd"))`) {
		t.Errorf("baseline profile should still allow trustd for cert validation\n%s", base)
	}

	optedIn := buildSeatbeltProfile(config.ExecConfig{Cmd: "/bin/true", AllowSecurityServices: true}, 0)
	for _, want := range []string{
		`(allow mach-lookup (global-name "com.apple.SecurityServer"))`,
		`(allow mach-lookup (global-name "com.apple.system.opendirectoryd"))`,
		`(allow mach-lookup (global-name "com.apple.memberd"))`,
	} {
		if !strings.Contains(optedIn, want) {
			t.Errorf("allowSecurityServices profile missing %s\n%s", want, optedIn)
		}
	}
}
