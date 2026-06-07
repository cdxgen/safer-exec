// Package config_test validates the JSON config parsing and validation.
package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestExecConfigJSONRoundtrip(t *testing.T) {
	original := ExecConfig{
		Cmd:            "npm",
		Args:           []string{"install", "--ignore-scripts"},
		Env:            map[string]string{"NODE_ENV": "production"},
		ReadPaths:      []string{"/usr", "/etc/ssl/certs"},
		WritePaths:     []string{"/tmp/app-out"},
		AllowHosts:     []string{"registry.npmjs.org"},
		AllowIPs:       []string{"93.184.216.34", "8.8.8.8"},
		AllowPorts:     []int{80, 443},
		DisableNetwork: false,
		MaxMemoryMB:    512,
		MaxCPUCores:    0.5,
		MaxProcesses:   100,
		TimeoutMs:      30000,
		WorkingDir:     "/test/dir",
		EnableAudit:    true,
		EnableDiff:     true,
		EnableLearn:    false,
		Strict:         true,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ExecConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Cmd != original.Cmd {
		t.Errorf("Cmd: got %q, want %q", decoded.Cmd, original.Cmd)
	}
	if len(decoded.Args) != len(original.Args) {
		t.Errorf("Args length: got %d, want %d", len(decoded.Args), len(original.Args))
	}
	if decoded.MaxMemoryMB != original.MaxMemoryMB {
		t.Errorf("MaxMemoryMB: got %d, want %d", decoded.MaxMemoryMB, original.MaxMemoryMB)
	}
	if decoded.DisableNetwork != original.DisableNetwork {
		t.Errorf("DisableNetwork: got %v, want %v", decoded.DisableNetwork, original.DisableNetwork)
	}
	if decoded.MaxCPUCores != original.MaxCPUCores {
		t.Errorf("MaxCPUCores: got %f, want %f", decoded.MaxCPUCores, original.MaxCPUCores)
	}
	if decoded.MaxProcesses != original.MaxProcesses {
		t.Errorf("MaxProcesses: got %d, want %d", decoded.MaxProcesses, original.MaxProcesses)
	}
	if decoded.TimeoutMs != original.TimeoutMs {
		t.Errorf("TimeoutMs: got %d, want %d", decoded.TimeoutMs, original.TimeoutMs)
	}
	if !decoded.EnableAudit {
		t.Error("EnableAudit: got false, want true")
	}
	if !decoded.EnableDiff {
		t.Error("EnableDiff: got false, want true")
	}
	if decoded.EnableLearn {
		t.Error("EnableLearn: got true, want false")
	}
	if len(decoded.AllowPorts) != 2 {
		t.Errorf("AllowPorts length: got %d, want 2", len(decoded.AllowPorts))
	}
	if !decoded.Strict {
		t.Error("Strict: got false, want true")
	}
}

func TestExecConfigEmptyJSON(t *testing.T) {
	var cfg ExecConfig
	if err := json.Unmarshal([]byte("{}"), &cfg); err != nil {
		t.Fatalf("empty JSON should parse: %v", err)
	}
	if cfg.Cmd != "" {
		t.Errorf("empty cmd expected, got %q", cfg.Cmd)
	}
}

func TestExecConfigMinimalJSON(t *testing.T) {
	input := `{"cmd":"echo","args":["hello"]}`

	var cfg ExecConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("minimal JSON should parse: %v", err)
	}

	if cfg.Cmd != "echo" {
		t.Errorf("Cmd: got %q, want %q", cfg.Cmd, "echo")
	}
	if len(cfg.Args) != 1 || cfg.Args[0] != "hello" {
		t.Errorf("Args: got %v, want [\"hello\"]", cfg.Args)
	}
}

func TestExecConfigFullJSON(t *testing.T) {
	input := `{
		"cmd": "npm",
		"args": ["install", "--ignore-scripts"],
		"env": {"NODE_ENV": "production"},
		"readPaths": ["/usr", "/etc/ssl/certs"],
		"writePaths": ["/tmp/app-out"],
		"allowHosts": ["registry.npmjs.org"],
		"allowIPs": ["93.184.216.34", "8.8.8.8"],
		"allowPorts": [80, 443],
		"disableNetwork": false,
		"maxMemoryMB": 512,
		"maxCPUCores": 0.5,
		"maxProcesses": 100,
		"timeoutMs": 30000,
		"workingDir": "/test/dir",
		"enableAudit": true,
		"enableDiff": true,
		"enableLearn": false
	}`

	var cfg ExecConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("full JSON should parse: %v", err)
	}

	if cfg.Cmd != "npm" {
		t.Errorf("Cmd: got %q, want %q", cfg.Cmd, "npm")
	}
	if len(cfg.Args) != 2 {
		t.Errorf("Args length: got %d, want 2", len(cfg.Args))
	}
	if len(cfg.Env) != 1 || cfg.Env["NODE_ENV"] != "production" {
		t.Errorf("Env: got %v, want {NODE_ENV: production}", cfg.Env)
	}
	if len(cfg.ReadPaths) != 2 {
		t.Errorf("ReadPaths length: got %d, want 2", len(cfg.ReadPaths))
	}
	if len(cfg.WritePaths) != 1 {
		t.Errorf("WritePaths length: got %d, want 1", len(cfg.WritePaths))
	}
	if len(cfg.AllowIPs) != 2 {
		t.Errorf("AllowIPs length: got %d, want 2", len(cfg.AllowIPs))
	}
	if cfg.MaxMemoryMB != 512 {
		t.Errorf("MaxMemoryMB: got %d, want 512", cfg.MaxMemoryMB)
	}
	if cfg.MaxCPUCores != 0.5 {
		t.Errorf("MaxCPUCores: got %f, want 0.5", cfg.MaxCPUCores)
	}
	if cfg.MaxProcesses != 100 {
		t.Errorf("MaxProcesses: got %d, want 100", cfg.MaxProcesses)
	}
	if cfg.TimeoutMs != 30000 {
		t.Errorf("TimeoutMs: got %d, want 30000", cfg.TimeoutMs)
	}
	if cfg.WorkingDir != "/test/dir" {
		t.Errorf("WorkingDir: got %q, want %q", cfg.WorkingDir, "/test/dir")
	}
	if !cfg.EnableAudit {
		t.Error("EnableAudit: got false, want true")
	}
	if !cfg.EnableDiff {
		t.Error("EnableDiff: got false, want true")
	}
	if cfg.EnableLearn {
		t.Error("EnableLearn: got true, want false")
	}
	if len(cfg.AllowPorts) != 2 {
		t.Errorf("AllowPorts: got %v, want [80, 443]", cfg.AllowPorts)
	}
}

func TestExecConfigDisableNetwork(t *testing.T) {
	input := `{"cmd":"echo","disableNetwork":true}`

	var cfg ExecConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("JSON should parse: %v", err)
	}

	if !cfg.DisableNetwork {
		t.Error("DisableNetwork should be true")
	}
}

func TestExecConfigEnableAudit(t *testing.T) {
	input := `{"cmd":"echo","enableAudit":true}`

	var cfg ExecConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("JSON should parse: %v", err)
	}

	if !cfg.EnableAudit {
		t.Error("EnableAudit should be true")
	}
}

func TestExecConfigEnableDiff(t *testing.T) {
	input := `{"cmd":"echo","enableDiff":true}`

	var cfg ExecConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("JSON should parse: %v", err)
	}

	if !cfg.EnableDiff {
		t.Error("EnableDiff should be true")
	}
}

func TestExecConfigEnableLearn(t *testing.T) {
	input := `{"cmd":"echo","enableLearn":true}`

	var cfg ExecConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("JSON should parse: %v", err)
	}

	if !cfg.EnableLearn {
		t.Error("EnableLearn should be true")
	}
}

func TestExecConfigAllowPorts(t *testing.T) {
	input := `{"cmd":"echo","allowPorts":[80,443,8080]}`

	var cfg ExecConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("JSON should parse: %v", err)
	}

	if len(cfg.AllowPorts) != 3 {
		t.Errorf("AllowPorts length: got %d, want 3", len(cfg.AllowPorts))
	}
	if cfg.AllowPorts[0] != 80 {
		t.Errorf("AllowPorts[0]: got %d, want 80", cfg.AllowPorts[0])
	}
}

func TestExecConfigInvalidJSON(t *testing.T) {
	input := `{"cmd":"echo","args":[invalid]}`

	var cfg ExecConfig
	if err := json.Unmarshal([]byte(input), &cfg); err == nil {
		t.Error("invalid JSON should return error")
	}
}

func TestAuditEntryJSON(t *testing.T) {
	entry := AuditEntry{
		Type:   "file-read",
		Target: "/etc/hosts",
		Detail: "read inside sandbox",
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("failed to marshal AuditEntry: %v", err)
	}

	var decoded AuditEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal AuditEntry: %v", err)
	}

	if decoded.Type != "file-read" {
		t.Errorf("Type: got %q, want 'file-read'", decoded.Type)
	}
	if decoded.Target != "/etc/hosts" {
		t.Errorf("Target: got %q, want '/etc/hosts'", decoded.Target)
	}
	if decoded.Detail != "read inside sandbox" {
		t.Errorf("Detail: got %q, want 'read inside sandbox'", decoded.Detail)
	}
}

func TestAuditResultJSON(t *testing.T) {
	result := AuditResult{
		AuditLog: []AuditEntry{
			{Type: "file-read", Target: "/etc/hosts"},
			{Type: "network-connect", Target: "93.184.216.34:443"},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal AuditResult: %v", err)
	}

	var decoded AuditResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal AuditResult: %v", err)
	}

	if len(decoded.AuditLog) != 2 {
		t.Errorf("AuditLog length: got %d, want 2", len(decoded.AuditLog))
	}
}

func TestFSDiffJSON(t *testing.T) {
	diff := FSDiff{
		Added: []FSDiffEntry{
			{Path: "/tmp/new_file.txt", Mode: 0o644, Size: 100, IsDir: false},
		},
		Modified: []FSDiffEntry{
			{Path: "/tmp/existing.txt", Mode: 0o644, Size: 200, IsDir: false},
		},
		Deleted: []FSDiffEntry{
			{Path: "/tmp/old_file.txt", Mode: 0o644, Size: 50, IsDir: false},
		},
	}

	data, err := json.Marshal(diff)
	if err != nil {
		t.Fatalf("failed to marshal FSDiff: %v", err)
	}

	var decoded FSDiff
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal FSDiff: %v", err)
	}

	if len(decoded.Added) != 1 {
		t.Errorf("Added length: got %d, want 1", len(decoded.Added))
	}
	if len(decoded.Modified) != 1 {
		t.Errorf("Modified length: got %d, want 1", len(decoded.Modified))
	}
	if len(decoded.Deleted) != 1 {
		t.Errorf("Deleted length: got %d, want 1", len(decoded.Deleted))
	}
}

func TestLearnedPolicyJSON(t *testing.T) {
	policy := LearnedPolicy{
		ReadPaths:  []string{"/usr", "/etc"},
		WritePaths: []string{"/tmp/output"},
		AllowHosts: []string{"registry.npmjs.org"},
		AllowIPs:   []string{"93.184.216.34"},
		AllowPorts: []int{443},
		EnvVars:    []string{"PATH", "HOME"},
		Cmd:        "npm",
		Args:       []string{"install"},
	}

	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("failed to marshal LearnedPolicy: %v", err)
	}

	var decoded LearnedPolicy
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal LearnedPolicy: %v", err)
	}

	if len(decoded.ReadPaths) != 2 {
		t.Errorf("ReadPaths length: got %d, want 2", len(decoded.ReadPaths))
	}
	if len(decoded.WritePaths) != 1 {
		t.Errorf("WritePaths length: got %d, want 1", len(decoded.WritePaths))
	}
	if decoded.Cmd != "npm" {
		t.Errorf("Cmd: got %q, want %q", decoded.Cmd, "npm")
	}
	if len(decoded.AllowIPs) != 1 {
		t.Errorf("AllowIPs length: got %d, want 1", len(decoded.AllowIPs))
	}
}

func TestExecResultJSON(t *testing.T) {
	result := ExecResult{
		Stdout:   "hello world",
		Stderr:   "warning: something",
		ExitCode: 0,
		AuditLog: []AuditEntry{
			{Type: "file-read", Target: "/etc/hosts"},
		},
		TimedOut: false,
		FSDiff: &FSDiff{
			Added: []FSDiffEntry{
				{Path: "/tmp/new.txt", Mode: 0o644, Size: 50},
			},
		},
		LearnedPolicy: &LearnedPolicy{
			ReadPaths:  []string{"/usr"},
			WritePaths: []string{"/tmp"},
			Cmd:        "echo",
			Args:       []string{"hello"},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal ExecResult: %v", err)
	}

	var decoded ExecResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal ExecResult: %v", err)
	}

	if decoded.Stdout != "hello world" {
		t.Errorf("Stdout: got %q, want 'hello world'", decoded.Stdout)
	}
	if decoded.ExitCode != 0 {
		t.Errorf("ExitCode: got %d, want 0", decoded.ExitCode)
	}
	if decoded.FSDiff == nil {
		t.Error("FSDiff should not be nil")
	} else if len(decoded.FSDiff.Added) != 1 {
		t.Errorf("FSDiff.Added length: got %d, want 1", len(decoded.FSDiff.Added))
	}
	if decoded.LearnedPolicy == nil {
		t.Error("LearnedPolicy should not be nil")
	} else if decoded.LearnedPolicy.Cmd != "echo" {
		t.Errorf("LearnedPolicy.Cmd: got %q, want 'echo'", decoded.LearnedPolicy.Cmd)
	}
}

func TestFilteredEnviron(t *testing.T) {
	os.Setenv("SECRET_LEAK_TEST_VAR", "super-secret-value")
	defer os.Unsetenv("SECRET_LEAK_TEST_VAR")

	filtered := FilteredEnviron()
	for _, env := range filtered {
		if strings.HasPrefix(env, "SECRET_LEAK_TEST_VAR=") {
			t.Errorf("secret var leaked into filtered environ: %s", env)
		}
	}
}

func TestBuildEnv(t *testing.T) {
	os.Setenv("SECRET_LEAK_TEST_VAR", "super-secret-value")
	defer os.Unsetenv("SECRET_LEAK_TEST_VAR")

	// Empty config env should return filtered environment
	built := BuildEnv(nil)
	foundSecret := false
	for _, env := range built {
		if strings.HasPrefix(env, "SECRET_LEAK_TEST_VAR=") {
			foundSecret = true
		}
	}
	if foundSecret {
		t.Error("BuildEnv with nil/empty map leaked secret host env variable")
	}

	// Custom config env should preserve path/home defaults and custom vars
	custom := map[string]string{
		"MY_CUSTOM_VAR": "custom-val",
	}
	builtCustom := BuildEnv(custom)
	foundCustom := false
	foundPath := false
	for _, env := range builtCustom {
		if strings.HasPrefix(env, "MY_CUSTOM_VAR=custom-val") {
			foundCustom = true
		}
		if strings.HasPrefix(env, "PATH=") {
			foundPath = true
		}
	}
	if !foundCustom {
		t.Error("custom variable was not found in built environment")
	}
	if !foundPath {
		t.Error("default PATH was not found in built environment")
	}
}
