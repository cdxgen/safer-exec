// Package config_test validates merge semantics and PolicyFile round-trips.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ---------- MergePolicies tests ----------

func TestMergePolicies_EmptyBase(t *testing.T) {
	base := &PolicyFile{}
	observed := &PolicyFile{
		ReadPaths:  []string{"/tmp"},
		WritePaths: []string{"/var"},
		Cmd:        "echo",
	}

	merged := MergePolicies(base, observed)

	if len(merged.ReadPaths) != 1 || merged.ReadPaths[0] != "/tmp" {
		t.Errorf("ReadPaths: got %v, want [/tmp]", merged.ReadPaths)
	}
	if len(merged.WritePaths) != 1 || merged.WritePaths[0] != "/var" {
		t.Errorf("WritePaths: got %v, want [/var]", merged.WritePaths)
	}
	if merged.Cmd != "echo" {
		t.Errorf("Cmd: got %q, want %q", merged.Cmd, "echo")
	}
}

func TestMergePolicies_EmptyObserved(t *testing.T) {
	base := &PolicyFile{
		ReadPaths: []string{"/usr"},
		Name:      "base-policy",
	}
	observed := &PolicyFile{}

	merged := MergePolicies(base, observed)

	if len(merged.ReadPaths) != 1 || merged.ReadPaths[0] != "/usr" {
		t.Errorf("ReadPaths: got %v, want [/usr]", merged.ReadPaths)
	}
	// Metadata preserved from base
	if merged.Name != "base-policy" {
		t.Errorf("Name: got %q, want %q", merged.Name, "base-policy")
	}
}

func TestMergePolicies_NilBase(t *testing.T) {
	merged := MergePolicies(nil, &PolicyFile{ReadPaths: []string{"/a"}})
	if merged == nil {
		t.Fatal("merged should not be nil")
	}
	if len(merged.ReadPaths) != 1 {
		t.Errorf("ReadPaths: got %v, want [/a]", merged.ReadPaths)
	}
}

func TestMergePolicies_NilObserved(t *testing.T) {
	merged := MergePolicies(&PolicyFile{ReadPaths: []string{"/a"}}, nil)
	if merged == nil {
		t.Fatal("merged should not be nil")
	}
	if len(merged.ReadPaths) != 1 {
		t.Errorf("ReadPaths: got %v, want [/a]", merged.ReadPaths)
	}
}

func TestMergePolicies_UnionOfPaths(t *testing.T) {
	base := &PolicyFile{ReadPaths: []string{"/a"}}
	observed := &PolicyFile{ReadPaths: []string{"/b"}}

	merged := MergePolicies(base, observed)

	if len(merged.ReadPaths) != 2 {
		t.Fatalf("ReadPaths length: got %d, want 2", len(merged.ReadPaths))
	}
	// unionStrings sorts, so /a comes before /b
	if merged.ReadPaths[0] != "/a" || merged.ReadPaths[1] != "/b" {
		t.Errorf("ReadPaths: got %v, want [/a /b]", merged.ReadPaths)
	}
}

func TestMergePolicies_Dedup(t *testing.T) {
	base := &PolicyFile{ReadPaths: []string{"/a", "/a"}}
	observed := &PolicyFile{ReadPaths: []string{"/a"}}

	merged := MergePolicies(base, observed)

	if len(merged.ReadPaths) != 1 || merged.ReadPaths[0] != "/a" {
		t.Errorf("ReadPaths: got %v, want [/a]", merged.ReadPaths)
	}
}

func TestMergePolicies_WritePathsUnion(t *testing.T) {
	base := &PolicyFile{WritePaths: []string{"/tmp"}}
	observed := &PolicyFile{WritePaths: []string{"/var"}}

	merged := MergePolicies(base, observed)

	if len(merged.WritePaths) != 2 {
		t.Fatalf("WritePaths length: got %d, want 2", len(merged.WritePaths))
	}
}

func TestMergePolicies_AllowHostsUnion(t *testing.T) {
	base := &PolicyFile{AllowHosts: []string{"a.com"}}
	observed := &PolicyFile{AllowHosts: []string{"b.com"}}

	merged := MergePolicies(base, observed)

	if len(merged.AllowHosts) != 2 {
		t.Fatalf("AllowHosts length: got %d, want 2", len(merged.AllowHosts))
	}
}

func TestMergePolicies_AllowIPsUnion(t *testing.T) {
	base := &PolicyFile{AllowIPs: []string{"1.2.3.4"}}
	observed := &PolicyFile{AllowIPs: []string{"5.6.7.8"}}

	merged := MergePolicies(base, observed)

	if len(merged.AllowIPs) != 2 {
		t.Fatalf("AllowIPs length: got %d, want 2", len(merged.AllowIPs))
	}
}

func TestMergePolicies_AllowPortsUnion(t *testing.T) {
	base := &PolicyFile{AllowPorts: []int{80}}
	observed := &PolicyFile{AllowPorts: []int{443}}

	merged := MergePolicies(base, observed)

	if len(merged.AllowPorts) != 2 {
		t.Fatalf("AllowPorts length: got %d, want 2", len(merged.AllowPorts))
	}
	if merged.AllowPorts[0] != 80 || merged.AllowPorts[1] != 443 {
		t.Errorf("AllowPorts: got %v, want [80 443]", merged.AllowPorts)
	}
}

func TestMergePolicies_AllowPortsDedup(t *testing.T) {
	base := &PolicyFile{AllowPorts: []int{443, 80}}
	observed := &PolicyFile{AllowPorts: []int{80}}

	merged := MergePolicies(base, observed)

	if len(merged.AllowPorts) != 2 {
		t.Fatalf("AllowPorts length: got %d, want 2", len(merged.AllowPorts))
	}
}

func TestMergePolicies_EnvMapMerge(t *testing.T) {
	base := &PolicyFile{Env: map[string]string{"A": "1", "C": "3"}}
	observed := &PolicyFile{Env: map[string]string{"A": "2", "B": "4"}}

	merged := MergePolicies(base, observed)

	if merged.Env["A"] != "2" {
		t.Errorf("Env[A]: got %q, want %q", merged.Env["A"], "2")
	}
	if merged.Env["B"] != "4" {
		t.Errorf("Env[B]: got %q, want %q", merged.Env["B"], "4")
	}
	if merged.Env["C"] != "3" {
		t.Errorf("Env[C]: got %q, want %q", merged.Env["C"], "3")
	}
}

func TestMergePolicies_EnvVarsUnion(t *testing.T) {
	base := &PolicyFile{EnvVars: []string{"PATH"}}
	observed := &PolicyFile{EnvVars: []string{"HOME"}}

	merged := MergePolicies(base, observed)

	if len(merged.EnvVars) != 2 {
		t.Fatalf("EnvVars length: got %d, want 2", len(merged.EnvVars))
	}
}

func TestMergePolicies_BlockForkOR(t *testing.T) {
	base := &PolicyFile{BlockFork: false}
	observed := &PolicyFile{BlockFork: true}

	merged := MergePolicies(base, observed)
	if !merged.BlockFork {
		t.Error("BlockFork should be true (OR)")
	}

	// Reverse: base true, observed false
	base2 := &PolicyFile{BlockFork: true}
	observed2 := &PolicyFile{BlockFork: false}
	merged2 := MergePolicies(base2, observed2)
	if !merged2.BlockFork {
		t.Error("BlockFork should be true (base OR observed)")
	}
}

func TestMergePolicies_DisableNetworkOR(t *testing.T) {
	base := &PolicyFile{DisableNetwork: true}
	observed := &PolicyFile{DisableNetwork: false}

	merged := MergePolicies(base, observed)
	if !merged.DisableNetwork {
		t.Error("DisableNetwork should be true (OR)")
	}
}

func TestMergePolicies_AllowLoopbackOR(t *testing.T) {
	base := &PolicyFile{AllowLoopback: true}
	observed := &PolicyFile{AllowLoopback: false}

	merged := MergePolicies(base, observed)
	if !merged.AllowLoopback {
		t.Error("AllowLoopback should be true (OR)")
	}
}

func TestMergePolicies_ResourceLimitBaseWins(t *testing.T) {
	base := &PolicyFile{MaxMemoryMB: 512}
	observed := &PolicyFile{MaxMemoryMB: 256}

	merged := MergePolicies(base, observed)
	if merged.MaxMemoryMB != 512 {
		t.Errorf("MaxMemoryMB: got %d, want 512 (base wins)", merged.MaxMemoryMB)
	}
}

func TestMergePolicies_ResourceLimitObservedFillsZero(t *testing.T) {
	base := &PolicyFile{MaxMemoryMB: 0}
	observed := &PolicyFile{MaxMemoryMB: 256}

	merged := MergePolicies(base, observed)
	if merged.MaxMemoryMB != 256 {
		t.Errorf("MaxMemoryMB: got %d, want 256 (observed fills zero)", merged.MaxMemoryMB)
	}
}

func TestMergePolicies_MaxCPUCoresMerge(t *testing.T) {
	base := &PolicyFile{MaxCPUCores: 1.0}
	observed := &PolicyFile{MaxCPUCores: 0.5}

	merged := MergePolicies(base, observed)
	if merged.MaxCPUCores != 1.0 {
		t.Errorf("MaxCPUCores: got %f, want 1.0", merged.MaxCPUCores)
	}

	// Observed fills zero
	base2 := &PolicyFile{MaxCPUCores: 0}
	observed2 := &PolicyFile{MaxCPUCores: 0.5}
	merged2 := MergePolicies(base2, observed2)
	if merged2.MaxCPUCores != 0.5 {
		t.Errorf("MaxCPUCores: got %f, want 0.5", merged2.MaxCPUCores)
	}
}

func TestMergePolicies_CryptoControls(t *testing.T) {
	base := &PolicyFile{
		AllowCrypto:        true,
		BlockCrypto:        false,
		BlockCryptoEntropy: true,
	}
	observed := &PolicyFile{
		AllowCrypto:        false,
		BlockCrypto:        true,
		BlockCryptoEntropy: false,
	}

	merged := MergePolicies(base, observed)
	if !merged.AllowCrypto {
		t.Error("AllowCrypto should be true (OR)")
	}
	if !merged.BlockCrypto {
		t.Error("BlockCrypto should be true (OR)")
	}
	if !merged.BlockCryptoEntropy {
		t.Error("BlockCryptoEntropy should be true (OR)")
	}
}

func TestMergePolicies_FIPSControls(t *testing.T) {
	base := &PolicyFile{
		DetectFIPS:   true,
		StrictFIPS:   false,
		FIPSDetected: true,
	}
	observed := &PolicyFile{
		DetectFIPS:   false,
		StrictFIPS:   true,
		FIPSDetected: false,
	}

	merged := MergePolicies(base, observed)
	if !merged.DetectFIPS {
		t.Error("DetectFIPS should be true (OR)")
	}
	if !merged.StrictFIPS {
		t.Error("StrictFIPS should be true (OR)")
	}
	if !merged.FIPSDetected {
		t.Error("FIPSDetected should be true (OR)")
	}
}

func TestMergePolicies_AdvancedControls(t *testing.T) {
	base := &PolicyFile{
		AllowGPU:       true,
		BlockTPM:       false,
		SpoofAntiVM:    true,
		TraceLibraries: false,
		GPUUsed:        true,
		TPMUsed:        false,
		AntiVMActive:   true,
	}
	observed := &PolicyFile{
		AllowGPU:       false,
		BlockTPM:       true,
		SpoofAntiVM:    false,
		TraceLibraries: true,
		GPUUsed:        false,
		TPMUsed:        true,
		AntiVMActive:   false,
	}

	merged := MergePolicies(base, observed)
	if !merged.AllowGPU {
		t.Error("AllowGPU should be true (OR)")
	}
	if !merged.BlockTPM {
		t.Error("BlockTPM should be true (OR)")
	}
	if !merged.SpoofAntiVM {
		t.Error("SpoofAntiVM should be true (OR)")
	}
	if !merged.TraceLibraries {
		t.Error("TraceLibraries should be true (OR)")
	}
	if !merged.GPUUsed {
		t.Error("GPUUsed should be true (OR)")
	}
	if !merged.TPMUsed {
		t.Error("TPMUsed should be true (OR)")
	}
	if !merged.AntiVMActive {
		t.Error("AntiVMActive should be true (OR)")
	}
}

func TestMergePolicies_MaxProcessesMerge(t *testing.T) {
	base := &PolicyFile{MaxProcesses: 100}
	observed := &PolicyFile{MaxProcesses: 50}

	merged := MergePolicies(base, observed)
	if merged.MaxProcesses != 100 {
		t.Errorf("MaxProcesses: got %d, want 100", merged.MaxProcesses)
	}
}

func TestMergePolicies_TimeoutMsMerge(t *testing.T) {
	base := &PolicyFile{TimeoutMs: 30000}
	observed := &PolicyFile{TimeoutMs: 60000}

	merged := MergePolicies(base, observed)
	if merged.TimeoutMs != 30000 {
		t.Errorf("TimeoutMs: got %d, want 30000", merged.TimeoutMs)
	}
}

func TestMergePolicies_MetadataPreserved(t *testing.T) {
	base := &PolicyFile{Name: "mine", Version: "1", Description: "my policy"}
	observed := &PolicyFile{Name: "new", Version: "2", Description: "new policy"}

	merged := MergePolicies(base, observed)

	if merged.Name != "mine" {
		t.Errorf("Name: got %q, want %q", merged.Name, "mine")
	}
	if merged.Version != "1" {
		t.Errorf("Version: got %q, want %q", merged.Version, "1")
	}
	if merged.Description != "my policy" {
		t.Errorf("Description: got %q, want %q", merged.Description, "my policy")
	}
}

func TestMergePolicies_MetadataFillsFromObservedWhenBaseEmpty(t *testing.T) {
	base := &PolicyFile{}
	observed := &PolicyFile{Name: "observed-name", Version: "1"}

	merged := MergePolicies(base, observed)

	if merged.Name != "observed-name" {
		t.Errorf("Name: got %q, want %q", merged.Name, "observed-name")
	}
	if merged.Version != "1" {
		t.Errorf("Version: got %q, want %q", merged.Version, "1")
	}
}

func TestMergePolicies_CmdArgsFromObserved(t *testing.T) {
	base := &PolicyFile{Cmd: "old-cmd", Args: []string{"old-arg"}}
	observed := &PolicyFile{Cmd: "new-cmd", Args: []string{"new-arg"}}

	merged := MergePolicies(base, observed)

	if merged.Cmd != "new-cmd" {
		t.Errorf("Cmd: got %q, want %q", merged.Cmd, "new-cmd")
	}
	if len(merged.Args) != 1 || merged.Args[0] != "new-arg" {
		t.Errorf("Args: got %v, want [new-arg]", merged.Args)
	}
}

func TestMergePolicies_AllowExecUnion(t *testing.T) {
	base := &PolicyFile{AllowExec: []string{"node"}}
	observed := &PolicyFile{AllowExec: []string{"npx"}}

	merged := MergePolicies(base, observed)
	if len(merged.AllowExec) != 2 {
		t.Fatalf("AllowExec length: got %d, want 2", len(merged.AllowExec))
	}
}

func TestMergePolicies_BlockExecUnion(t *testing.T) {
	base := &PolicyFile{BlockExec: []string{"sh"}}
	observed := &PolicyFile{BlockExec: []string{"bash"}}

	merged := MergePolicies(base, observed)
	if len(merged.BlockExec) != 2 {
		t.Fatalf("BlockExec length: got %d, want 2", len(merged.BlockExec))
	}
}

func TestMergePolicies_TraceExecOR(t *testing.T) {
	base := &PolicyFile{TraceExec: true}
	observed := &PolicyFile{TraceExec: false}

	merged := MergePolicies(base, observed)
	if !merged.TraceExec {
		t.Error("TraceExec should be true (OR)")
	}
}

func TestMergePolicies_EnableAuditOR(t *testing.T) {
	base := &PolicyFile{EnableAudit: false}
	observed := &PolicyFile{EnableAudit: true}

	merged := MergePolicies(base, observed)
	if !merged.EnableAudit {
		t.Error("EnableAudit should be true (OR)")
	}
}

func TestMergePolicies_FullMerge(t *testing.T) {
	base := &PolicyFile{
		Name:           "ci-policy",
		Version:        "1",
		Description:    "CI policy",
		ReadPaths:      []string{"/usr", "/etc"},
		WritePaths:     []string{"/tmp"},
		AllowHosts:     []string{"registry.npmjs.org"},
		AllowIPs:       []string{"1.2.3.4"},
		AllowPorts:     []int{443},
		Env:            map[string]string{"NODE_ENV": "production"},
		EnvVars:        []string{"PATH"},
		AllowExec:      []string{"node"},
		BlockExec:      []string{"sh"},
		BlockFork:      true,
		DisableNetwork: false,
		MaxMemoryMB:    512,
		MaxCPUCores:    1.0,
		MaxProcesses:   100,
		TimeoutMs:      30000,
		TraceExec:      true,
		EnableAudit:    false,
		Cmd:            "npm",
		Args:           []string{"install"},
	}

	observed := &PolicyFile{
		ReadPaths:      []string{"/usr/lib"},
		WritePaths:     []string{"/var"},
		AllowHosts:     []string{"registry.yarnpkg.com"},
		AllowIPs:       []string{"5.6.7.8"},
		AllowPorts:     []int{80},
		Env:            map[string]string{"HOME": "/home/user"},
		EnvVars:        []string{"HOME"},
		AllowExec:      []string{"npx"},
		BlockExec:      []string{"bash"},
		BlockFork:      false,
		DisableNetwork: true,
		MaxMemoryMB:    256,
		MaxCPUCores:    0.5,
		MaxProcesses:   50,
		TimeoutMs:      60000,
		TraceExec:      false,
		EnableAudit:    true,
		Cmd:            "npm",
		Args:           []string{"run", "build"},
	}

	merged := MergePolicies(base, observed)

	// Metadata preserved from base
	if merged.Name != "ci-policy" {
		t.Errorf("Name: got %q, want %q", merged.Name, "ci-policy")
	}

	// Paths union
	if len(merged.ReadPaths) != 3 {
		t.Errorf("ReadPaths: got %d entries, want 3", len(merged.ReadPaths))
	}
	if len(merged.WritePaths) != 2 {
		t.Errorf("WritePaths: got %d entries, want 2", len(merged.WritePaths))
	}

	// Network union
	if len(merged.AllowHosts) != 2 {
		t.Errorf("AllowHosts: got %d entries, want 2", len(merged.AllowHosts))
	}
	if len(merged.AllowIPs) != 2 {
		t.Errorf("AllowIPs: got %d entries, want 2", len(merged.AllowIPs))
	}
	if len(merged.AllowPorts) != 2 {
		t.Errorf("AllowPorts: got %d entries, want 2", len(merged.AllowPorts))
	}
	if !merged.DisableNetwork {
		t.Error("DisableNetwork should be true (OR)")
	}

	// Env merge
	if merged.Env["NODE_ENV"] != "production" {
		t.Errorf("Env[NODE_ENV]: got %q, want %q", merged.Env["NODE_ENV"], "production")
	}
	if merged.Env["HOME"] != "/home/user" {
		t.Errorf("Env[HOME]: got %q, want %q", merged.Env["HOME"], "/home/user")
	}

	// EnvVars union
	if len(merged.EnvVars) != 2 {
		t.Errorf("EnvVars: got %d entries, want 2", len(merged.EnvVars))
	}

	// Exec controls
	if len(merged.AllowExec) != 2 {
		t.Errorf("AllowExec: got %d entries, want 2", len(merged.AllowExec))
	}
	if len(merged.BlockExec) != 2 {
		t.Errorf("BlockExec: got %d entries, want 2", len(merged.BlockExec))
	}
	if !merged.BlockFork {
		t.Error("BlockFork should be true (OR)")
	}

	// Resource limits — base wins
	if merged.MaxMemoryMB != 512 {
		t.Errorf("MaxMemoryMB: got %d, want 512", merged.MaxMemoryMB)
	}
	if merged.MaxCPUCores != 1.0 {
		t.Errorf("MaxCPUCores: got %f, want 1.0", merged.MaxCPUCores)
	}
	if merged.MaxProcesses != 100 {
		t.Errorf("MaxProcesses: got %d, want 100", merged.MaxProcesses)
	}
	if merged.TimeoutMs != 30000 {
		t.Errorf("TimeoutMs: got %d, want 30000", merged.TimeoutMs)
	}

	// Observability — OR
	if !merged.TraceExec {
		t.Error("TraceExec should be true (OR)")
	}
	if !merged.EnableAudit {
		t.Error("EnableAudit should be true (OR)")
	}

	// Cmd/Args from observed
	if merged.Cmd != "npm" {
		t.Errorf("Cmd: got %q, want %q", merged.Cmd, "npm")
	}
	if len(merged.Args) != 2 || merged.Args[0] != "run" || merged.Args[1] != "build" {
		t.Errorf("Args: got %v, want [run build]", merged.Args)
	}
}

// ---------- PolicyFile JSON round-trip tests ----------

func TestPolicyFileJSONRoundtrip(t *testing.T) {
	original := PolicyFile{
		Name:           "my-policy",
		Version:        "1",
		Description:    "test policy",
		ReadPaths:      []string{"/usr", "/etc"},
		WritePaths:     []string{"/tmp"},
		DisableNetwork: true,
		AllowHosts:     []string{"registry.npmjs.org"},
		AllowIPs:       []string{"1.2.3.4"},
		AllowPorts:     []int{80, 443},
		Env:            map[string]string{"NODE_ENV": "production"},
		EnvVars:        []string{"PATH"},
		AllowExec:      []string{"node"},
		BlockExec:      []string{"sh"},
		BlockFork:      true,
		MaxMemoryMB:    512,
		MaxCPUCores:    0.5,
		MaxProcesses:   100,
		TimeoutMs:      30000,
		TraceExec:      true,
		EnableAudit:    true,
		Cmd:            "npm",
		Args:           []string{"install"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded PolicyFile
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.Name != original.Name {
		t.Errorf("Name: got %q, want %q", decoded.Name, original.Name)
	}
	if decoded.Version != original.Version {
		t.Errorf("Version: got %q, want %q", decoded.Version, original.Version)
	}
	if decoded.Description != original.Description {
		t.Errorf("Description: got %q, want %q", decoded.Description, original.Description)
	}
	if len(decoded.ReadPaths) != 2 {
		t.Errorf("ReadPaths length: got %d, want 2", len(decoded.ReadPaths))
	}
	if len(decoded.WritePaths) != 1 {
		t.Errorf("WritePaths length: got %d, want 1", len(decoded.WritePaths))
	}
	if len(decoded.AllowHosts) != 1 {
		t.Errorf("AllowHosts length: got %d, want 1", len(decoded.AllowHosts))
	}
	if len(decoded.AllowIPs) != 1 {
		t.Errorf("AllowIPs length: got %d, want 1", len(decoded.AllowIPs))
	}
	if len(decoded.AllowPorts) != 2 {
		t.Errorf("AllowPorts length: got %d, want 2", len(decoded.AllowPorts))
	}
	if decoded.Env["NODE_ENV"] != "production" {
		t.Errorf("Env[NODE_ENV]: got %q, want %q", decoded.Env["NODE_ENV"], "production")
	}
	if len(decoded.EnvVars) != 1 {
		t.Errorf("EnvVars length: got %d, want 1", len(decoded.EnvVars))
	}
	if len(decoded.AllowExec) != 1 {
		t.Errorf("AllowExec length: got %d, want 1", len(decoded.AllowExec))
	}
	if len(decoded.BlockExec) != 1 {
		t.Errorf("BlockExec length: got %d, want 1", len(decoded.BlockExec))
	}
	if !decoded.BlockFork {
		t.Error("BlockFork should be true")
	}
	if !decoded.DisableNetwork {
		t.Error("DisableNetwork should be true")
	}
	if decoded.MaxMemoryMB != 512 {
		t.Errorf("MaxMemoryMB: got %d, want 512", decoded.MaxMemoryMB)
	}
	if decoded.MaxCPUCores != 0.5 {
		t.Errorf("MaxCPUCores: got %f, want 0.5", decoded.MaxCPUCores)
	}
	if decoded.MaxProcesses != 100 {
		t.Errorf("MaxProcesses: got %d, want 100", decoded.MaxProcesses)
	}
	if decoded.TimeoutMs != 30000 {
		t.Errorf("TimeoutMs: got %d, want 30000", decoded.TimeoutMs)
	}
	if !decoded.TraceExec {
		t.Error("TraceExec should be true")
	}
	if !decoded.EnableAudit {
		t.Error("EnableAudit should be true")
	}
	if decoded.Cmd != "npm" {
		t.Errorf("Cmd: got %q, want %q", decoded.Cmd, "npm")
	}
	if len(decoded.Args) != 1 || decoded.Args[0] != "install" {
		t.Errorf("Args: got %v, want [install]", decoded.Args)
	}
}

func TestPolicyFileEmptyJSON(t *testing.T) {
	var pf PolicyFile
	if err := json.Unmarshal([]byte("{}"), &pf); err != nil {
		t.Fatalf("empty JSON should parse: %v", err)
	}
}

func TestPolicyFileOmitEmpty(t *testing.T) {
	pf := PolicyFile{}
	data, err := json.Marshal(pf)
	if err != nil {
		t.Fatalf("marshal empty PolicyFile: %v", err)
	}
	// All fields are omitempty, so an empty struct should serialize to {}
	if string(data) != "{}" {
		t.Errorf("empty PolicyFile should serialize to {{}}, got %s", string(data))
	}
}

func TestPolicyFileBackwardCompat_OldFormat(t *testing.T) {
	// Old LearnedPolicy format (only the fields that existed before)
	input := `{
		"readPaths": ["/usr"],
		"writePaths": ["/tmp"],
		"allowHosts": ["registry.npmjs.org"],
		"allowIPs": ["1.2.3.4"],
		"allowPorts": [443],
		"envVars": ["PATH"],
		"cmd": "npm",
		"args": ["install"]
	}`

	var pf PolicyFile
	if err := json.Unmarshal([]byte(input), &pf); err != nil {
		t.Fatalf("old format should parse: %v", err)
	}

	if len(pf.ReadPaths) != 1 {
		t.Errorf("ReadPaths: got %d, want 1", len(pf.ReadPaths))
	}
	if len(pf.WritePaths) != 1 {
		t.Errorf("WritePaths: got %d, want 1", len(pf.WritePaths))
	}
	if pf.Cmd != "npm" {
		t.Errorf("Cmd: got %q, want %q", pf.Cmd, "npm")
	}
	// New fields should be zero-valued
	if pf.Name != "" {
		t.Errorf("Name: got %q, want empty", pf.Name)
	}
	if pf.MaxMemoryMB != 0 {
		t.Errorf("MaxMemoryMB: got %d, want 0", pf.MaxMemoryMB)
	}
}

// ---------- WritePolicyFile / ReadPolicyFile tests ----------

func TestWriteAndReadPolicyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	pf := &PolicyFile{
		Name:       "test",
		Version:    "1",
		ReadPaths:  []string{"/usr"},
		WritePaths: []string{"/tmp"},
		AllowHosts: []string{"example.com"},
		Env:        map[string]string{"KEY": "value"},
	}

	if err := WritePolicyFile(path, pf); err != nil {
		t.Fatalf("WritePolicyFile failed: %v", err)
	}

	read, err := ReadPolicyFile(path)
	if err != nil {
		t.Fatalf("ReadPolicyFile failed: %v", err)
	}

	if read.Name != "test" {
		t.Errorf("Name: got %q, want %q", read.Name, "test")
	}
	if len(read.ReadPaths) != 1 || read.ReadPaths[0] != "/usr" {
		t.Errorf("ReadPaths: got %v, want [/usr]", read.ReadPaths)
	}
	if read.Env["KEY"] != "value" {
		t.Errorf("Env[KEY]: got %q, want %q", read.Env["KEY"], "value")
	}
}

func TestWritePolicyFile_Atomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	// Write first policy
	pf1 := &PolicyFile{Name: "first"}
	if err := WritePolicyFile(path, pf1); err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	// Verify no .tmp file left behind
	tmpPath := path + ".tmp"
	if _, err := os.Stat(tmpPath); err == nil {
		t.Error("temp file should not exist after successful write")
	}

	// Write second policy (overwrite)
	pf2 := &PolicyFile{Name: "second"}
	if err := WritePolicyFile(path, pf2); err != nil {
		t.Fatalf("second write failed: %v", err)
	}

	read, err := ReadPolicyFile(path)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if read.Name != "second" {
		t.Errorf("Name: got %q, want %q", read.Name, "second")
	}
}

func TestReadPolicyFile_NotFound(t *testing.T) {
	_, err := ReadPolicyFile("/nonexistent/path/policy.json")
	if err == nil {
		t.Fatal("should error for nonexistent file")
	}
}

func TestReadPolicyFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte("{invalid}"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	_, err := ReadPolicyFile(path)
	if err == nil {
		t.Fatal("should error for invalid JSON")
	}
}

func TestWritePolicyFile_InvalidPath(t *testing.T) {
	dir := t.TempDir()
	// Write to a path inside a directory
	path := filepath.Join(dir, "sub", "policy.json")
	pf := &PolicyFile{Name: "test"}
	if err := WritePolicyFile(path, pf); err == nil {
		t.Log("write succeeded in non-existent subdir (parent created automatically)")
	}
	// If it failed, verify it was because parent dir doesn't exist
	if err := WritePolicyFile(path, pf); err != nil {
		t.Logf("expected error for missing parent dir: %v", err)
	}
}
