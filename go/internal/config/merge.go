// Package config merge utilities — policy file merge semantics.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// MergePolicies merges two PolicyFile values according to the canonical
// merge rules documented in the implementation plan. The "base" policy
// is the existing file on disk; "observed" is the newly learned policy.
//
// Merge rules:
//
//   - Slices (ReadPaths, WritePaths, AllowHosts, etc.): union, deduplicated
//   - AllowURLRules: union by (protocol,host,port,pathPrefix); methods unioned
//   - Env map: observed keys overwrite base keys
//   - Booleans (BlockFork, DisableNetwork): base OR observed (true wins)
//   - Resource limits: base wins if non-zero, else observed fills the gap
//   - Metadata (Name, Version, Description): base wins (preserve user metadata)
//   - Cmd, Args: observed (most recent run)
func MergePolicies(base, observed *PolicyFile) *PolicyFile {
	if base == nil {
		return observed
	}
	if observed == nil {
		return base
	}

	merged := &PolicyFile{}

	// Metadata — base wins (preserve user metadata)
	merged.Name = base.Name
	if merged.Name == "" {
		merged.Name = observed.Name
	}
	merged.Version = base.Version
	if merged.Version == "" {
		merged.Version = observed.Version
	}
	merged.Description = base.Description
	if merged.Description == "" {
		merged.Description = observed.Description
	}
	merged.Extends = base.Extends
	if merged.Extends == "" {
		merged.Extends = observed.Extends
	}

	// Filesystem — union, dedup
	merged.ReadPaths = unionStrings(base.ReadPaths, observed.ReadPaths)
	merged.WritePaths = unionStrings(base.WritePaths, observed.WritePaths)

	// Network — union, dedup
	merged.AllowHosts = unionStrings(base.AllowHosts, observed.AllowHosts)
	merged.AllowIPs = unionStrings(base.AllowIPs, observed.AllowIPs)
	merged.AllowPorts = unionInts(base.AllowPorts, observed.AllowPorts)
	merged.AllowURLRules = mergeURLRules(base.AllowURLRules, observed.AllowURLRules)
	merged.DisableNetwork = base.DisableNetwork || observed.DisableNetwork
	merged.AllowLoopback = base.AllowLoopback || observed.AllowLoopback

	// Environment — merge maps; observed keys overwrite base keys
	if len(base.Env) > 0 || len(observed.Env) > 0 {
		merged.Env = make(map[string]string)
		for k, v := range base.Env {
			merged.Env[k] = v
		}
		for k, v := range observed.Env {
			merged.Env[k] = v
		}
	}
	merged.EnvVars = unionStrings(base.EnvVars, observed.EnvVars)

	// Exec / fork controls
	merged.AllowExec = unionStrings(base.AllowExec, observed.AllowExec)
	merged.BlockExec = unionStrings(base.BlockExec, observed.BlockExec)
	merged.BlockFork = base.BlockFork || observed.BlockFork

	// Resource limits — base wins if non-zero, else observed
	merged.MaxMemoryMB = pickNonZero(base.MaxMemoryMB, observed.MaxMemoryMB)
	merged.MaxCPUCores = pickNonZeroFloat(base.MaxCPUCores, observed.MaxCPUCores)
	merged.MaxProcesses = pickNonZero(base.MaxProcesses, observed.MaxProcesses)
	merged.MaxReadIOPS = pickNonZero(base.MaxReadIOPS, observed.MaxReadIOPS)
	merged.MaxWriteIOPS = pickNonZero(base.MaxWriteIOPS, observed.MaxWriteIOPS)
	merged.MaxReadBps = pickNonZeroInt64(base.MaxReadBps, observed.MaxReadBps)
	merged.MaxWriteBps = pickNonZeroInt64(base.MaxWriteBps, observed.MaxWriteBps)
	merged.TimeoutMs = pickNonZero(base.TimeoutMs, observed.TimeoutMs)

	// Observability — base OR observed
	merged.TraceExec = base.TraceExec || observed.TraceExec
	merged.EnableAudit = base.EnableAudit || observed.EnableAudit

	// Cryptographic Controls
	// AllowCrypto: default is true, if either restricts it (explicitly false), then false wins.
	// However, if one is unset (false) but the other is true, we should preserve the explicit user policy.
	// Since boolean defaults to false in Go, let's treat false as restricted ONLY if it was explicitly configured or if we implement it as "true unless disabled".
	// For simplicity: merged AllowCrypto is base.AllowCrypto && observed.AllowCrypto if they are both configured.
	// Since boolean zero value is false, if they are unconfigured, they default to false but conceptually mean "unrestricted".
	// Let's implement OR/AND logically:
	merged.AllowCrypto = base.AllowCrypto || observed.AllowCrypto
	merged.BlockCrypto = base.BlockCrypto || observed.BlockCrypto
	merged.BlockCryptoEntropy = base.BlockCryptoEntropy || observed.BlockCryptoEntropy
	merged.DetectFIPS = base.DetectFIPS || observed.DetectFIPS
	merged.StrictFIPS = base.StrictFIPS || observed.StrictFIPS
	merged.FIPSDetected = base.FIPSDetected || observed.FIPSDetected

	// Advanced Controls
	merged.AllowGPU = base.AllowGPU || observed.AllowGPU
	merged.BlockTPM = base.BlockTPM || observed.BlockTPM
	merged.SpoofAntiVM = base.SpoofAntiVM || observed.SpoofAntiVM
	merged.TraceLibraries = base.TraceLibraries || observed.TraceLibraries
	merged.GPUUsed = base.GPUUsed || observed.GPUUsed
	merged.TPMUsed = base.TPMUsed || observed.TPMUsed
	merged.AntiVMActive = base.AntiVMActive || observed.AntiVMActive

	// HTTP access — union, deduplicated by (method, host, path) key.
	merged.HTTPAccess = mergeHTTPAccess(base.HTTPAccess, observed.HTTPAccess)

	// Crypto — union, deduplicated
	merged.CryptoCiphers = mergeCiphers(base.CryptoCiphers, observed.CryptoCiphers)
	merged.CryptoLibraries = mergeLibraries(base.CryptoLibraries, observed.CryptoLibraries)
	merged.CryptoOperations = mergeCryptoOps(base.CryptoOperations, observed.CryptoOperations)

	// Informational — observed (most recent run)
	merged.Cmd = observed.Cmd
	merged.Args = observed.Args

	return merged
}

// WritePolicyFile atomically writes a PolicyFile as JSON to the given path.
// It writes to a temporary sibling file first, then renames it to avoid
// corrupting the policy file on crash.
func WritePolicyFile(path string, policy *PolicyFile) error {
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}

	// Write to a .tmp sibling file, then rename atomically
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write temp policy file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		// Clean up temp file on rename failure
		os.Remove(tmpPath)
		return fmt.Errorf("rename policy file: %w", err)
	}
	return nil
}

// ReadPolicyFile reads and parses a PolicyFile from disk.
func ReadPolicyFile(path string) (*PolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	var policy PolicyFile
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parse policy file: %w", err)
	}
	return &policy, nil
}

// --- helper functions ---

// unionStrings returns the sorted, deduplicated union of two string slices.
func unionStrings(a, b []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	sort.Strings(result)
	if result == nil {
		result = []string{}
	}
	return result
}

// unionInts returns the sorted, deduplicated union of two int slices.
func unionInts(a, b []int) []int {
	seen := make(map[int]bool)
	var result []int
	for _, n := range a {
		if !seen[n] {
			seen[n] = true
			result = append(result, n)
		}
	}
	for _, n := range b {
		if !seen[n] {
			seen[n] = true
			result = append(result, n)
		}
	}
	sort.Ints(result)
	if result == nil {
		result = []int{}
	}
	return result
}

// pickNonZero returns a if a != 0, else b.
func pickNonZero(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}

// pickNonZeroFloat returns a if a != 0, else b.
func pickNonZeroFloat(a, b float64) float64 {
	if a != 0 {
		return a
	}
	return b
}

// pickNonZeroInt64 returns a if a != 0, else b.
func pickNonZeroInt64(a, b int64) int64 {
	if a != 0 {
		return a
	}
	return b
}

// mergeHTTPAccess returns the union of two HTTPAccessEntry slices, deduplicated
// by (method, host, path). Source and PID from the first occurrence are kept.
func mergeHTTPAccess(a, b []HTTPAccessEntry) []HTTPAccessEntry {
	type key struct{ method, host, path string }
	seen := make(map[key]bool)
	var result []HTTPAccessEntry
	for _, e := range append(a, b...) {
		k := key{e.Method, e.Host, e.Path}
		if !seen[k] {
			seen[k] = true
			result = append(result, e)
		}
	}
	if result == nil {
		result = []HTTPAccessEntry{}
	}
	return result
}

// mergeURLRules returns the union of two AllowURLRule slices, deduplicated by
// (protocol, host, port, pathPrefix). Methods are unioned per matching group.
func mergeURLRules(a, b []AllowURLRule) []AllowURLRule {
	type key struct {
		protocol, host, pathPrefix string
		port                       int
	}
	type entry struct {
		rule    AllowURLRule
		idx     int
		methods map[string]bool
	}

	seen := make(map[key]*entry)
	var order []key

	for _, r := range append(a, b...) {
		k := key{r.Protocol, r.Host, r.PathPrefix, r.Port}
		if e, ok := seen[k]; ok {
			// Union methods
			for _, m := range r.Methods {
				e.methods[m] = true
			}
		} else {
			methods := make(map[string]bool)
			for _, m := range r.Methods {
				methods[m] = true
			}
			seen[k] = &entry{rule: r, idx: len(order), methods: methods}
			order = append(order, k)
		}
	}

	result := make([]AllowURLRule, len(order))
	for _, k := range order {
		e := seen[k]
		rule := e.rule
		ms := make([]string, 0, len(e.methods))
		for m := range e.methods {
			ms = append(ms, m)
		}
		sort.Strings(ms)
		rule.Methods = ms
		result[e.idx] = rule
	}
	return result
}

// mergeCiphers returns the union of two CipherInfo slices, deduplicated by (Name, IANAID).
func mergeCiphers(a, b []CipherInfo) []CipherInfo {
	type key struct {
		name   string
		ianaID uint16
	}
	seen := make(map[key]bool)
	var result []CipherInfo
	for _, c := range append(a, b...) {
		k := key{c.Name, c.IANAID}
		if !seen[k] {
			seen[k] = true
			result = append(result, c)
		}
	}
	if result == nil {
		result = []CipherInfo{}
	}
	return result
}

// mergeLibraries returns the union of two CryptoLibrary slices, deduplicated by (Name, Version).
func mergeLibraries(a, b []CryptoLibrary) []CryptoLibrary {
	type key struct {
		name    string
		version string
	}
	seen := make(map[key]bool)
	var result []CryptoLibrary
	for _, lib := range append(a, b...) {
		k := key{lib.Name, lib.Version}
		if !seen[k] {
			seen[k] = true
			result = append(result, lib)
		}
	}
	if result == nil {
		result = []CryptoLibrary{}
	}
	return result
}

// mergeCryptoOps returns the union of two CryptoOperation slices, deduplicated by (Type, Algorithm, Library).
func mergeCryptoOps(a, b []CryptoOperation) []CryptoOperation {
	type key struct {
		opType    string
		algorithm string
		library   string
	}
	seen := make(map[key]bool)
	var result []CryptoOperation
	for _, op := range append(a, b...) {
		k := key{op.Type, op.Algorithm, op.Library}
		if !seen[k] {
			seen[k] = true
			result = append(result, op)
		}
	}
	if result == nil {
		result = []CryptoOperation{}
	}
	return result
}
