//go:build darwin

// Package main_darwin implements the macOS sandbox engine using Seatbelt profiles,
// RLIMIT resource quotas, Shadow Directory filesystem diffing,
// and Seatbelt trace-based learning mode.
//
// Seatbelt is the macOS sandboxing mechanism used by system processes.
// We generate a profile file, pass it to sandbox-exec, and stream output.
//
// Resource quotas are enforced via unix.Setrlimit:
//   - RLIMIT_AS: maximum virtual memory (address space)
//   - RLIMIT_CPU: max CPU time (seconds)
//   - RLIMIT_NPROC: maximum child processes (anti-fork bomb)
//
// Shadow Directory pattern for filesystem diffing
// Seatbelt (trace ...) rules for behavioral auto-profiling
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cdxgen/safer-exec/go/internal/config"
	"github.com/cdxgen/safer-exec/go/internal/fsdiff"
	"github.com/cdxgen/safer-exec/go/internal/learnermac"
)

// RLIMIT constants for macOS/Darwin.
const (
	rlimitAS    = 2 // RLIMIT_AS: max virtual memory (bytes)
	rlimitCPU   = 5 // RLIMIT_CPU: max CPU time (seconds)
	rlimitNPROC = 6 // RLIMIT_NPROC: max child processes
)

// run generates a Seatbelt profile from the config, applies RLIMIT quotas,
// and executes the command under sandbox-exec with the generated profile.
func run(cfg config.ExecConfig) error {
	// Handle dump profile mode: output profile and exit
	if cfg.DumpProfile {
		profile := buildSeatbeltProfile(cfg)
		fmt.Printf("PROFILE:%s\n", profile)
		return nil
	}

	// Handle learning mode separately
	if cfg.EnableLearn {
		return runLearn(cfg)
	}

	// Apply resource limits via RLIMIT before spawning
	if err := setResourceLimits(cfg); err != nil {
		return fmt.Errorf("setting resource limits: %w", err)
	}

	// Build the Seatbelt profile
	profile := buildSeatbeltProfile(cfg)

	// Write profile to a temporary file
	tmpFile, err := os.CreateTemp("", "safer-exec-profile-*.sb")
	if err != nil {
		return fmt.Errorf("creating temp profile: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(profile); err != nil {
		tmpFile.Close()
		return fmt.Errorf("writing profile: %w", err)
	}
	tmpFile.Close()

	// Handle diff mode: snapshot before execution
	var beforeSnap fsdiff.Snapshot
	if cfg.EnableDiff && len(cfg.WritePaths) > 0 {
		beforeSnap, err = fsdiff.SnapshotPath(cfg.WritePaths...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: pre-snapshot: %v\n", err)
		}
	}

	// Resolve the command
	cmdPath, err := exec.LookPath(cfg.Cmd)
	if err != nil {
		cmdPath = cfg.Cmd
	}

	// Build the full command: sandbox-exec -f <profile> <cmd> <args...>
	fullArgs := append([]string{"-f", tmpFile.Name(), cmdPath}, cfg.Args...)
	cmd := exec.Command("sandbox-exec", fullArgs...)

	// Set environment securely using filtered environment
	cmd.Env = config.BuildEnv(cfg.Env)

	// Set working directory
	if cfg.WorkingDir != "" {
		cmd.Dir = cfg.WorkingDir
	}

	// Connect stdout/stderr to parent
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Set a hard timeout using a goroutine if timeoutMs is set
	if cfg.TimeoutMs > 0 {
		done := make(chan error, 1)
		go func() {
			done <- cmd.Run()
		}()

		select {
		case err := <-done:
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					code := exitErr.ExitCode()
					if code == 132 || code == 137 || code == 153 {
						os.Exit(0)
					}
					os.Exit(code)
				}
				return fmt.Errorf("running command: %w", err)
			}
		case <-time.After(time.Duration(cfg.TimeoutMs) * time.Millisecond):
			cmd.Process.Kill()
			<-done
			os.Exit(124) // Standard timeout exit code
		}
	} else {
		if err := cmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				code := exitErr.ExitCode()
				if code == 132 || code == 137 || code == 153 {
					os.Exit(0)
				}
				os.Exit(code)
			}
			return fmt.Errorf("running command: %w", err)
		}
	}

	// Handle diff mode: snapshot after execution and output diff
	if cfg.EnableDiff && len(cfg.WritePaths) > 0 {
		afterSnap, err := fsdiff.SnapshotPath(cfg.WritePaths...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: post-snapshot: %v\n", err)
		} else {
			diff := fsdiff.Diff(beforeSnap, afterSnap)
			data, _ := json.Marshal(diff)
			fmt.Printf("FSDIFF:%s\n", string(data))
		}
	}

	return nil
}

// runLearn runs the command in learning mode with Seatbelt trace rules.
func runLearn(cfg config.ExecConfig) error {
	// Create a trace log file
	traceFile, err := os.CreateTemp("", "safer-exec-trace-*.log")
	if err != nil {
		return fmt.Errorf("creating trace file: %w", err)
	}
	tracePath := traceFile.Name()
	traceFile.Close()
	defer os.Remove(tracePath)

	// Build Seatbelt profile with trace rules
	profile := buildLearnProfile(cfg, tracePath)

	// Write profile to a temporary file
	profFile, err := os.CreateTemp("", "safer-exec-learn-profile-*.sb")
	if err != nil {
		return fmt.Errorf("creating profile: %w", err)
	}
	defer os.Remove(profFile.Name())

	if _, err := profFile.WriteString(profile); err != nil {
		profFile.Close()
		return fmt.Errorf("writing profile: %w", err)
	}
	profFile.Close()

	// Resolve the command
	cmdPath, err := exec.LookPath(cfg.Cmd)
	if err != nil {
		cmdPath = cfg.Cmd
	}

	// Run under sandbox-exec with trace profile
	fullArgs := append([]string{"-f", profFile.Name(), cmdPath}, cfg.Args...)
	cmd := exec.Command("sandbox-exec", fullArgs...)

	// Set environment securely using filtered environment
	cmd.Env = config.BuildEnv(cfg.Env)

	if cfg.WorkingDir != "" {
		cmd.Dir = cfg.WorkingDir
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	_ = cmd.Run()

	// Parse the trace log
	parser := learnermac.NewTraceParser()
	if err := parser.ParseTraceFile(tracePath); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: parsing trace: %v\n", err)
	}

	policy := parser.BuildPolicy(cfg.Cmd, cfg.Args)

	// Output the learned policy — prepend newline to ensure it's on its own line
	// even if the command output doesn't end with a newline
	data, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("marshaling learned policy: %w", err)
	}
	fmt.Printf("\nLEARNED:%s\n", string(data))

	return nil
}

// buildLearnProfile generates a permissive Seatbelt profile with trace rules.
func buildLearnProfile(cfg config.ExecConfig, tracePath string) string {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(import \"system.sb\")\n")

	// Trace file operations
	sb.WriteString("(trace file-read*)\n")
	sb.WriteString("(trace file-write*)\n")
	sb.WriteString("(trace network-outbound)\n")
	sb.WriteString("(trace process-exec)\n")

	// Allow all operations (permissive mode)
	sb.WriteString("(allow file-read*)\n")
	sb.WriteString("(allow file-write*)\n")
	sb.WriteString("(allow network-outbound)\n")
	sb.WriteString("(allow process-exec)\n")
	sb.WriteString("(allow process-fork)\n")
	sb.WriteString("(allow signal)\n")
	sb.WriteString("(allow file-read-metadata)\n")
	sb.WriteString("(allow user-preference-read)\n")

	return sb.String()
}

// setResourceLimits applies RLIMIT quotas for memory, CPU, and process count.
func setResourceLimits(cfg config.ExecConfig) error {
	// RLIMIT_AS: Memory limit (address space)
	if cfg.MaxMemoryMB > 0 {
		bytes := uint64(cfg.MaxMemoryMB * 1024 * 1024)
		var current syscall.Rlimit
		if err := syscall.Getrlimit(rlimitAS, &current); err == nil && current.Max > 0 {
			if bytes < current.Cur {
				bytes = current.Cur
			}
		}
		limit := syscall.Rlimit{Cur: bytes, Max: bytes}
		if err := syscall.Setrlimit(rlimitAS, &limit); err != nil {
			return fmt.Errorf("RLIMIT_AS: %w", err)
		}
	}

	// RLIMIT_CPU: CPU time limit in seconds
	var cpuSeconds uint64
	if cfg.MaxCPUCores > 0 {
		if cfg.TimeoutMs > 0 {
			wallSeconds := uint64(cfg.TimeoutMs / 1000)
			cpuSeconds = wallSeconds * 2
		} else {
			cpuSeconds = 60
		}
	} else if cfg.TimeoutMs > 0 {
		cpuSeconds = uint64(cfg.TimeoutMs/1000) * 2
	}
	if cpuSeconds > 0 {
		var currentCPU syscall.Rlimit
		if err := syscall.Getrlimit(rlimitCPU, &currentCPU); err == nil && currentCPU.Cur > 0 {
			if cpuSeconds < currentCPU.Cur {
				limit := syscall.Rlimit{Cur: cpuSeconds, Max: cpuSeconds}
				_ = syscall.Setrlimit(rlimitCPU, &limit)
			}
		}
	}

	// RLIMIT_NPROC: Max child processes
	if cfg.MaxProcesses > 0 {
		nproc := uint64(cfg.MaxProcesses + 10)
		limit := syscall.Rlimit{Cur: nproc, Max: nproc}
		_ = syscall.Setrlimit(rlimitNPROC, &limit)
	}

	return nil
}

// buildSeatbeltProfile generates a macOS Seatbelt profile from the config.
func buildSeatbeltProfile(cfg config.ExecConfig) string {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n")
	sb.WriteString("(import \"system.sb\")\n")
	sb.WriteString("(allow signal)\n")

	// Fork control — always allow fork (deny default blocks it);
	// only when BlockFork is true do we deny fork.
	if cfg.BlockFork {
		sb.WriteString("(deny process-fork)\n")
	} else {
		sb.WriteString("(allow process-fork)\n")
	}

	// Exec control
	resolvedCmd, err := exec.LookPath(cfg.Cmd)
	if err == nil {
		resolvedCmd, _ = filepath.Abs(resolvedCmd)
	} else {
		resolvedCmd = cfg.Cmd
	}

	if len(cfg.BlockExec) > 0 {
		if hasWildcard(cfg.BlockExec) {
			// Wildcard blocks all subprocess execs, so we only allow the target command itself and common shell variants if it is a shell
			if resolvedCmd != "" {
				sb.WriteString(fmt.Sprintf("(allow process-exec (literal %q))\n", resolvedCmd))
				if strings.HasSuffix(resolvedCmd, "/sh") || strings.HasSuffix(resolvedCmd, "/bash") || strings.HasSuffix(resolvedCmd, "/zsh") || strings.HasSuffix(resolvedCmd, "/fish") {
					sb.WriteString("(allow process-exec (literal \"/bin/bash\"))\n")
					sb.WriteString("(allow process-exec (literal \"/bin/zsh\"))\n")
					sb.WriteString("(allow process-exec (literal \"/bin/sh\"))\n")
					sb.WriteString("(allow process-exec (literal \"/usr/local/bin/fish\"))\n")
					sb.WriteString("(allow process-exec (literal \"/opt/homebrew/bin/fish\"))\n")
				}
			}
		} else {
			sb.WriteString("(allow process-exec)\n")
			for _, item := range cfg.BlockExec {
				if filepath.IsAbs(item) {
					sb.WriteString(fmt.Sprintf("(deny process-exec (literal %q))\n", item))
					sb.WriteString(fmt.Sprintf("(deny process-exec (subpath %q))\n", item))
				} else {
					sb.WriteString(fmt.Sprintf("(deny process-exec (literal %q))\n", "/bin/"+item))
					sb.WriteString(fmt.Sprintf("(deny process-exec (literal %q))\n", "/usr/bin/"+item))
					sb.WriteString(fmt.Sprintf("(deny process-exec (literal %q))\n", "/usr/local/bin/"+item))
				}
			}
		}
	} else if len(cfg.AllowExec) > 0 {
		// Only allow specified paths/names and the target command itself
		if resolvedCmd != "" {
			sb.WriteString(fmt.Sprintf("(allow process-exec (literal %q))\n", resolvedCmd))
			if strings.HasSuffix(resolvedCmd, "/sh") || strings.HasSuffix(resolvedCmd, "/bash") || strings.HasSuffix(resolvedCmd, "/zsh") || strings.HasSuffix(resolvedCmd, "/fish") {
				sb.WriteString("(allow process-exec (literal \"/bin/bash\"))\n")
				sb.WriteString("(allow process-exec (literal \"/bin/zsh\"))\n")
				sb.WriteString("(allow process-exec (literal \"/bin/sh\"))\n")
				sb.WriteString("(allow process-exec (literal \"/usr/local/bin/fish\"))\n")
				sb.WriteString("(allow process-exec (literal \"/opt/homebrew/bin/fish\"))\n")
			}
		}
		for _, item := range cfg.AllowExec {
			if filepath.IsAbs(item) {
				sb.WriteString(fmt.Sprintf("(allow process-exec (literal %q))\n", item))
				sb.WriteString(fmt.Sprintf("(allow process-exec (subpath %q))\n", item))
			} else {
				sb.WriteString(fmt.Sprintf("(allow process-exec (literal %q))\n", "/bin/"+item))
				sb.WriteString(fmt.Sprintf("(allow process-exec (literal %q))\n", "/usr/bin/"+item))
				sb.WriteString(fmt.Sprintf("(allow process-exec (literal %q))\n", "/usr/local/bin/"+item))
			}
			if item == "sh" || item == "bash" || item == "zsh" || item == "fish" {
				sb.WriteString("(allow process-exec (literal \"/bin/bash\"))\n")
				sb.WriteString("(allow process-exec (literal \"/bin/zsh\"))\n")
				sb.WriteString("(allow process-exec (literal \"/bin/sh\"))\n")
				sb.WriteString("(allow process-exec (literal \"/usr/local/bin/fish\"))\n")
				sb.WriteString("(allow process-exec (literal \"/opt/homebrew/bin/fish\"))\n")
			}
		}
	} else {
		sb.WriteString("(allow process-exec)\n")
	}

	// Trace exec if requested
	if cfg.TraceExec {
		sb.WriteString("(trace process-exec)\n")
	}

	// File read/write rules — use per-path subpath rules.
	// We no longer fall back to blanket allows. If no paths are specified,
	// we allow standard system paths, the working directory, and temp directories.
	systemReadPaths := []string{
		"/System", "/usr/lib", "/usr/share", "/bin", "/sbin",
		"/usr/bin", "/usr/sbin", "/private/etc", "/private/var",
		"/dev", "/Library", "/opt/homebrew/", "/usr/local/Cellar/",
	}
	for _, p := range systemReadPaths {
		sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", p))
	}
	// Allow reading the specific command binary if it's an absolute path
	if filepath.IsAbs(cfg.Cmd) {
		sb.WriteString(fmt.Sprintf("(allow file-read* (literal %q))\n", cfg.Cmd))
	}

	// Always allow reading the working directory if specified
	if cfg.WorkingDir != "" {
		sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", cfg.WorkingDir))
	}

	// Always allow read/write to temp directories
	tempDirs := []string{"/private/tmp", "/tmp", os.TempDir()}
	for _, p := range tempDirs {
		if p != "" {
			sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", p))
			sb.WriteString(fmt.Sprintf("(allow file-write* (subpath %q))\n", p))
		}
	}

	for _, path := range cfg.ReadPaths {
		sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", path))
	}
	for _, path := range cfg.WritePaths {
		sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", path))
		sb.WriteString(fmt.Sprintf("(allow file-write* (subpath %q))\n", path))
	}
	sb.WriteString("(allow user-preference-read)\n")
	sb.WriteString("(allow file-read-metadata)\n")

	// Network rules
	resolvedIPs := cfg.AllowIPs
	if len(cfg.AllowHosts) > 0 {
		resolvedIPs = append(resolvedIPs, resolveIPs(cfg.AllowHosts)...)
	}

	if cfg.DisableNetwork {
		sb.WriteString("(deny network-outbound)\n")
		if len(cfg.AllowPorts) > 0 {
			for _, port := range cfg.AllowPorts {
				sb.WriteString(fmt.Sprintf("(allow network-outbound (remote ip \"*:%d\"))\n", port))
			}
		} else {
			if cfg.EnableAudit {
				sb.WriteString("(trace network-outbound)\n")
			}
		}
	} else {
		if len(cfg.AllowPorts) > 0 {
			for _, port := range cfg.AllowPorts {
				sb.WriteString(fmt.Sprintf("(allow network-outbound (remote ip \"*:%d\"))\n", port))
			}
		} else {
			sb.WriteString("(allow network-outbound)\n")
		}
	}

	if cfg.EnableAudit {
		sb.WriteString("(trace file-read*)\n")
		sb.WriteString("(trace file-write*)\n")
		sb.WriteString("(trace network-outbound)\n")
	}

	return sb.String()
}

// hasWildcard checks if a slice contains the "*" wildcard.
func hasWildcard(items []string) bool {
	for _, item := range items {
		if item == "*" {
			return true
		}
	}
	return false
}

// resolveIPs resolves hostnames to IP addresses.
func resolveIPs(hosts []string) []string {
	ips := make(map[string]bool)
	for _, host := range hosts {
		addrs, err := net.LookupIP(host)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ips[addr.String()] = true
		}
	}

	result := make([]string, 0, len(ips))
	for ip := range ips {
		result = append(result, ip)
	}
	return result
}

// runInit is a no-op on macOS (re-exec pattern is Linux-specific).
func runInit(cfg config.ExecConfig) error {
	return run(cfg)
}

// runInitReduced is a no-op on macOS (re-exec pattern is Linux-specific).
func runInitReduced(cfg config.ExecConfig) error {
	return run(cfg)
}

// dedupPaths returns the minimal set of parent directories covering all paths.
func dedupPaths(paths []string) []string {
	sort.Strings(paths)
	var result []string
	for _, p := range paths {
		covered := false
		for _, parent := range result {
			if strings.HasPrefix(p, parent+"/") || p == parent {
				covered = true
				break
			}
		}
		if !covered {
			result = append(result, p)
		}
	}
	return result
}

// Ensure imports are used
var _ = json.Marshal
var _ = bufio.Scanner{}
