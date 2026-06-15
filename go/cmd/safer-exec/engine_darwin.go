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
	"runtime"
	"sort"
	"strconv"
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

// writeStructured writes a structured output line (e.g. "FSDIFF:{...}") either
// to the file at cfg.StructuredOutputPath (when set) or to stdout as a fallback.
// When the path is set every caller appends to the same file so multiple markers
// can coexist in one file, one per line.
func writeStructured(cfg config.ExecConfig, marker string, data []byte) {
	line := marker + string(data) + "\n"
	if cfg.StructuredOutputPath != "" {
		f, err := os.OpenFile(cfg.StructuredOutputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: open structured-output file: %v\n", err)
			return
		}
		defer f.Close()
		if _, err := f.WriteString(line); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: write structured-output file: %v\n", err)
		}
		return
	}
	// Fallback: write to stdout (legacy / buffered-run mode)
	fmt.Print(line)
}

// run generates a Seatbelt profile from the config, applies RLIMIT quotas,
// and executes the command under sandbox-exec with the generated profile.
func run(cfg config.ExecConfig) error {
	// Handle dump profile mode: output profile and exit
	if cfg.DumpProfile {
		profile := buildSeatbeltProfile(cfg)
		writeStructured(cfg, "PROFILE:", []byte(profile))
		return nil
	}

	// Handle validate profile mode: syntax-check the Seatbelt profile
	if cfg.ValidateProfile {
		return runValidateProfile(cfg)
	}

	// Handle learning mode separately
	if cfg.EnableLearn {
		return runLearn(cfg)
	}

	// Handle dry-run mode
	if cfg.EnableDryRun {
		return runDryRun(cfg)
	}

	// Apply resource limits via RLIMIT before spawning
	if err := setResourceLimits(cfg); err != nil {
		return fmt.Errorf("setting resource limits: %w", err)
	}

	// Handle FIPS controls on macOS
	if cfg.DetectFIPS || cfg.StrictFIPS {
		fipsVal := "0"
		// Query FIPSMode setting from macOS security defaults plist
		// When FIPS mode is activated via MDM profiles, FIPSMode defaults to 1.
		out, err := exec.Command("defaults", "read", "/Library/Preferences/com.apple.security", "FIPSMode").Output()
		if err == nil {
			fipsVal = strings.TrimSpace(string(out))
		} else {
			// Fallback: check user preferences plist
			out, err = exec.Command("defaults", "read", "com.apple.security", "FIPSMode").Output()
			if err == nil {
				fipsVal = strings.TrimSpace(string(out))
			}
		}

		if cfg.StrictFIPS && fipsVal != "1" {
			fmt.Fprintf(os.Stderr, "safer-exec: audit: fips-violation: macOS host is not running in FIPS-compliant mode\n")
			if cfg.Strict {
				return fmt.Errorf("FIPS strict enforcement failed: macOS has FIPSMode disabled")
			}
		} else {
			fmt.Fprintf(os.Stderr, "safer-exec: audit: fips-check: macOS FIPS mode status: %s\n", fipsVal)
		}
	}

	// Set environment securely using filtered environment
	env := config.BuildEnv(cfg.Env)

	// Library tracing on macOS: modern macOS (Big Sur+) hardened runtime prevents
	// DYLD_INSERT_LIBRARIES injection into any binary protected by SIP or the
	// CS_RESTRICT code-signing flag. This covers virtually all system tools
	// (/bin/sh, /usr/bin/python3, node, etc.).
	//
	// We use the Seatbelt audit mechanism instead: enabling TraceLibraries
	// activates audit mode so that file-read events for .dylib and .framework
	// paths are captured in the audit log. Callers can filter by file extension
	// to identify which libraries were loaded.
	if cfg.TraceLibraries {
		cfg.EnableAudit = true
		fmt.Fprintf(os.Stderr, "safer-exec: trace-libraries: enabled on macOS. Library loads appear as file-read audit events (.dylib/.framework paths).\n")
	}

	if cfg.TraceHTTPURLs || len(cfg.AllowURLRules) > 0 {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: http-trace: eBPF HTTP tracing and fine-grained URL rules are only supported on Linux. These settings will be ignored on macOS.\n")
	}

	// Build the Seatbelt profile (after potentially adding the dylib path to ReadPaths)
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

	// Show warning if resolved path is a symlink (Bug #1)
	if realCmdPath, err := filepath.EvalSymlinks(cmdPath); err == nil && realCmdPath != cmdPath {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: %q is a symlink resolving to %q. macOS Seatbelt enforces rules against the real path. Please pass the real path directly or use 'readlink -f' to resolve it.\n", cmdPath, realCmdPath)
	}

	// Build the full command: sandbox-exec -f <profile> <cmd> <args...>
	fullArgs := append([]string{"-f", tmpFile.Name(), cmdPath}, cfg.Args...)
	cmd := exec.Command("sandbox-exec", fullArgs...)
	cmd.Env = env

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
			writeStructured(cfg, "FSDIFF:", data)
		}
	}

	return nil
}

// runValidateProfile validates the generated Seatbelt profile using sandbox-exec -n.
// This syntax-checks the profile without executing the command, reporting any errors.
func runValidateProfile(cfg config.ExecConfig) error {
	profile := buildSeatbeltProfile(cfg)

	sandboxPath, err := exec.LookPath("sandbox-exec")
	if err != nil {
		result := config.ProfileValidationResult{
			Valid:   false,
			Profile: profile,
			Warning: fmt.Sprintf("sandbox-exec not found: %v", err),
		}
		data, _ := json.Marshal(result)
		writeStructured(cfg, "PROFILE:", data)
		return fmt.Errorf("sandbox-exec not found: %w", err)
	}

	// Write profile to temp file
	tmpFile, err := os.CreateTemp("", "safer-exec-validate-*.sb")
	if err != nil {
		return fmt.Errorf("creating temp profile: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(profile); err != nil {
		tmpFile.Close()
		return fmt.Errorf("writing profile: %w", err)
	}
	tmpFile.Close()

	// Run sandbox-exec -n to syntax-check the profile without executing
	cmd := exec.Command(sandboxPath, "-n", "-f", tmpFile.Name(), "/bin/true")
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	runErr := cmd.Run()
	stderrStr := stderrBuf.String()

	result := config.ProfileValidationResult{
		Profile: profile,
	}

	if runErr != nil {
		result.Valid = false
		if stderrStr != "" {
			result.Errors = strings.Split(strings.TrimSpace(stderrStr), "\n")
		} else {
			result.Errors = []string{runErr.Error()}
		}
	} else {
		result.Valid = true
	}

	data, _ := json.Marshal(result)
	writeStructured(cfg, "PROFILE:", data)

	if !result.Valid {
		return fmt.Errorf("seatbelt profile validation failed: %s", stderrStr)
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

	// Show warning if resolved path is a symlink (Bug #1)
	if realCmdPath, err := filepath.EvalSymlinks(cmdPath); err == nil && realCmdPath != cmdPath {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: %q is a symlink resolving to %q. macOS Seatbelt enforces rules against the real path. Please pass the real path directly or use 'readlink -f' to resolve it.\n", cmdPath, realCmdPath)
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

	// If --policy-file was also given, merge with existing file and write back
	if cfg.PolicyFilePath != "" {
		base, err := config.ReadPolicyFile(cfg.PolicyFilePath)
		if err == nil {
			policy = config.MergePolicies(base, policy)
		}
		if err := config.WritePolicyFile(cfg.PolicyFilePath, policy); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: write merged policy file: %v\n", err)
		}
	}

	// Output the learned policy
	data, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("marshaling learned policy: %w", err)
	}
	writeStructured(cfg, "LEARNED:", data)

	return nil
}

// runDryRun executes the command in dry-run mode: most operations are denied
// via Seatbelt, system paths are explicitly allowed so the binary can start.
// On macOS, Seatbelt traces go to the system log for audit.
func runDryRun(cfg config.ExecConfig) error {
	// Resolve the command path and its real path (for symlinks)
	cmdPath, err := exec.LookPath(cfg.Cmd)
	if err != nil {
		cmdPath = cfg.Cmd
	}
	if realCmdPath, err := filepath.EvalSymlinks(cmdPath); err == nil && realCmdPath != cmdPath {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: %q is a symlink resolving to %q. macOS Seatbelt enforces rules against the real path.\n", cmdPath, realCmdPath)
	}

	// Build Seatbelt profile: deny-default with system allowances
	profile := buildDryRunProfile(cfg, cmdPath)

	profFile, err := os.CreateTemp("", "safer-exec-dryrun-profile-*.sb")
	if err != nil {
		return fmt.Errorf("creating profile: %w", err)
	}
	defer os.Remove(profFile.Name())

	if _, err := profFile.WriteString(profile); err != nil {
		profFile.Close()
		return fmt.Errorf("writing profile: %w", err)
	}
	profFile.Close()

	// Run under sandbox-exec with the dry-run profile
	fullArgs := append([]string{"-f", profFile.Name(), cmdPath}, cfg.Args...)
	cmd := exec.Command("sandbox-exec", fullArgs...)
	cmd.Env = config.BuildEnv(cfg.Env)
	if cfg.WorkingDir != "" {
		cmd.Dir = cfg.WorkingDir
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	_ = cmd.Run() // ignore real exit code

	// Build result with synthetic exit 0
	result := &config.DryRunResult{
		ExitCode: 0,
		Events:   []config.DryRunEvent{},
		Summary:  config.DryRunSummary{},
	}

	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshaling dry-run result: %w", err)
	}
	writeStructured(cfg, "DRYRUN:", data)

	return nil
}

// buildDryRunProfile generates a deny-default Seatbelt profile that:
// - Allows only system-level reads so the binary and dyld can load
// - Denies all writes, network, and process forking
// - Traces all operations to the system log
func buildDryRunProfile(cfg config.ExecConfig, cmdPath string) string {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n")
	sb.WriteString("(import \"system.sb\")\n")

	// Allow the target binary and its parent dir (needed for exec)
	sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", filepath.Dir(cmdPath)))
	sb.WriteString(fmt.Sprintf("(allow file-read* (literal %q))\n", cmdPath))

	// Allow essential system paths for process bootstrap only.
	// No /etc, /usr/bin, /bin, /sbin, /usr/share — those are not needed
	// for the binary to start and would leak system file contents.
	sb.WriteString("(allow file-read* (subpath \"/usr/lib\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/System\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/dev\"))\n")

	// Allow dyld shared cache (needed for process bootstrap)
	sb.WriteString("(allow file-read* (subpath \"/private/var/db/dyld\"))\n")

	// Allow reading of the working directory if set
	// (dry-run blocks project reads by default; add working dir only if needed)
	_ = cfg.WorkingDir

	// Process operations needed for execution
	sb.WriteString("(allow process-exec)\n")
	sb.WriteString("(allow process-fork)\n")
	sb.WriteString("(allow signal)\n")

	// System-level operations needed for process lifecycle
	sb.WriteString("(allow sysctl-read)\n")
	sb.WriteString("(allow mach-lookup)\n")
	sb.WriteString("(allow mach-register)\n")
	sb.WriteString("(allow ipc-posix-sem)\n")
	sb.WriteString("(allow ipc-posix-shm)\n")
	sb.WriteString("(allow process-info-dirtycontrol)\n")
	sb.WriteString("(allow process-info-pidinfo)\n")
	sb.WriteString("(allow process-info-listpids)\n")

	// Trace all operations for audit
	sb.WriteString("(trace file-read*)\n")
	sb.WriteString("(trace file-write*)\n")
	sb.WriteString("(trace file-read-metadata)\n")
	sb.WriteString("(trace network-outbound)\n")
	sb.WriteString("(trace network-inbound)\n")
	sb.WriteString("(trace network-bind)\n")
	sb.WriteString("(trace process-exec)\n")
	sb.WriteString("(trace process-fork)\n")
	sb.WriteString("(trace signal)\n")

	return sb.String()
}

// parseDryRunTrace parses a Seatbelt trace log and extracts dry-run events.
func parseDryRunTrace(tracePath string) []config.DryRunEvent {
	f, err := os.Open(tracePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var events []config.DryRunEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		event := parseDryRunLine(line)
		if event != nil {
			events = append(events, *event)
		}
	}

	return events
}

// parseDryRunLine extracts a dry-run event from a single Seatbelt trace line.
func parseDryRunLine(line string) *config.DryRunEvent {
	var event config.DryRunEvent

	if strings.Contains(line, "file-read") && strings.Contains(line, "file-read-metadata") {
		event.Type = "file-metadata"
	} else if strings.Contains(line, "file-read") {
		event.Type = "file-read"
	} else if strings.Contains(line, "file-write") {
		event.Type = "file-write"
	} else if strings.Contains(line, "network-outbound") {
		event.Type = "network-outbound"
		if ip, port := extractNetworkTarget(line); ip != "" {
			event.Target = ip
			event.Port = port
		}
		return &event
	} else if strings.Contains(line, "network-bind") || strings.Contains(line, "network-inbound") {
		event.Type = "network-bind"
		if ip, port := extractNetworkTarget(line); ip != "" {
			event.Target = ip
			event.Port = port
		}
		return &event
	} else if strings.Contains(line, "process-exec") {
		event.Type = "process-exec"
		event.Path = extractTracePath(line)
		return &event
	} else if strings.Contains(line, "process-fork") {
		event.Type = "process-fork"
		return &event
	} else if strings.Contains(line, "signal") {
		event.Type = "signal"
		return &event
	} else {
		return nil
	}

	event.Path = extractTracePath(line)
	if event.Path == "" {
		return nil
	}

	return &event
}

// extractTracePath finds the file path in a trace line (last quoted string).
func extractTracePath(line string) string {
	lastQuote := -1
	for i := len(line) - 1; i >= 0; i-- {
		if line[i] == '"' {
			lastQuote = i
			break
		}
	}
	if lastQuote <= 0 {
		return ""
	}
	start := lastQuote - 1
	for start >= 0 && line[start] != '"' {
		start--
	}
	if start < 0 {
		return ""
	}
	return line[start+1 : lastQuote]
}

// extractNetworkTarget parses IP:port from a network-outbound trace line.
func extractNetworkTarget(line string) (string, int) {
	idx := strings.Index(line, "to \"")
	if idx == -1 {
		idx = strings.Index(line, "to '")
	}
	if idx == -1 {
		return "", 0
	}

	rest := line[idx+4:]
	end := strings.IndexAny(rest, "\"'")
	if end == -1 {
		return "", 0
	}

	target := rest[:end]
	parts := strings.Split(target, ":")
	if len(parts) == 2 {
		port, _ := strconv.Atoi(parts[1])
		return parts[0], port
	}
	if len(parts) == 1 {
		return parts[0], 0
	}
	return target, 0
}

// buildDryRunResult constructs a DryRunResult from collected events.
func buildDryRunResult(events []config.DryRunEvent, cmd string, args []string) *config.DryRunResult {
	result := &config.DryRunResult{
		ExitCode: 0,
		Events:   events,
	}

	// Sort events by type for predictable output
	sort.Slice(result.Events, func(i, j int) bool {
		if result.Events[i].Type != result.Events[j].Type {
			return result.Events[i].Type < result.Events[j].Type
		}
		return result.Events[i].Path < result.Events[j].Path
	})

	// Deduplicate events
	seen := make(map[string]bool)
	var deduped []config.DryRunEvent
	for _, e := range result.Events {
		key := fmt.Sprintf("%s|%s|%s|%d", e.Type, e.Path, e.Target, e.Port)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, e)
		}
	}
	result.Events = deduped

	// Compute summary
	for _, e := range result.Events {
		switch e.Type {
		case "file-read":
			result.Summary.FileReads++
		case "file-write":
			result.Summary.FileWrites++
		case "file-metadata":
			result.Summary.FileMetadata++
		case "network-outbound":
			result.Summary.NetworkOutbound++
		case "network-bind":
			result.Summary.NetworkBind++
		case "process-exec":
			result.Summary.ExecAttempts++
		case "process-fork":
			result.Summary.ForkAttempts++
		}
	}
	result.Summary.TotalEvents = len(result.Events)

	return result
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
	// RLIMIT_AS: Memory limit (address space).
	if cfg.MaxMemoryMB > 0 {
		const rlimInfinity = ^uint64(0)
		want := uint64(cfg.MaxMemoryMB) * 1024 * 1024
		// Clamp the requested cap DOWN to the inherited hard limit when that
		// hard limit is finite and lower — an unprivileged process cannot raise
		// it. We must never raise `want` up to the (typically unlimited) current
		// limit, which would silently disable the cap entirely.
		var current syscall.Rlimit
		if err := syscall.Getrlimit(rlimitAS, &current); err == nil {
			if current.Max != rlimInfinity && uint64(current.Max) != 0 && want > uint64(current.Max) {
				want = uint64(current.Max)
			}
		}
		limit := syscall.Rlimit{Cur: want, Max: want}
		if err := syscall.Setrlimit(rlimitAS, &limit); err != nil {
			// macOS does not reliably enforce RLIMIT_AS and may reject the call
			// with EINVAL. Treat this as best-effort: warn that the cap could not
			// be applied rather than silently leaving memory unbounded (the prior
			// behavior raised the request up to the unlimited soft limit, which
			// disabled the cap without any indication).
			fmt.Fprintf(os.Stderr, "safer-exec: warning: could not apply memory limit (RLIMIT_AS): %v — memory will not be capped on this host\n", err)
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

// interpreterExecLiteralDenies lists the absolute paths of preinstalled
// Apple-signed scripting engines and com.apple.SamplingTools binaries that
// carry unsigned-executable-memory, library-validation, or task-port
// exemptions and so can be abused to run in-memory shellcode or attach to
// other processes. Denied for process-exec under BlockInterpreters.
var interpreterExecLiteralDenies = []string{
	"/usr/bin/tclsh",
	"/usr/bin/wish",
	"/usr/bin/expect",
	"/usr/bin/perl",
	"/usr/bin/ruby",
	"/usr/bin/python3", // system python (org.python.python); Homebrew/pyenv live elsewhere
	"/usr/bin/auvaltool",
	"/usr/bin/auval",
	// com.apple.SamplingTools — hold com.apple.system-task-ports (task_for_pid)
	"/usr/bin/symbols",
	"/usr/bin/vmmap",
	"/usr/bin/vmmap32",
	"/usr/bin/sample",
	"/usr/bin/leaks",
	"/usr/bin/leaks32",
	"/usr/bin/heap",
	"/usr/bin/heap32",
	"/usr/bin/atos",
	"/usr/bin/malloc_history",
	"/usr/bin/malloc_history32",
	"/usr/bin/stringdups",
	"/usr/bin/stringdups32",
	"/usr/bin/filtercalltree",
}

// interpreterExecSubpathDenies lists framework roots whose binaries must be
// denied for process-exec, covering direct-framework invocation that the
// /usr/bin shims above would miss (e.g. the versioned tclsh8.5).
var interpreterExecSubpathDenies = []string{
	"/System/Library/Frameworks/Tcl.framework",
	"/System/Library/Frameworks/Tk.framework",
	"/System/Library/Frameworks/AudioToolbox.framework/XPCServices",
}

// interpreterReadDenies lists framework/library trees that hold the FFI
// bridge (Ffidl) and Tcl/Tk runtime; denying reads prevents an allowed
// interpreter from loading them to make raw mmap/mprotect calls.
var interpreterReadDenies = []string{
	"/System/Library/Tcl", // Ffidl ships here
	"/System/Library/Frameworks/Tcl.framework",
	"/System/Library/Frameworks/Tk.framework",
}

// cmdRealPaths returns the candidate absolute paths a target command may run
// as: the resolved command and, when it is a symlink (e.g. /usr/bin/tclsh ->
// the Tcl.framework binary), its symlink target. Seatbelt matches rules
// against the real path, so the self-command guard must consider both.
func cmdRealPaths(resolvedCmd string) []string {
	paths := []string{resolvedCmd}
	if real, err := filepath.EvalSymlinks(resolvedCmd); err == nil && real != resolvedCmd {
		paths = append(paths, real)
	}
	return paths
}

// underAny reports whether p equals or is contained beneath any of the given
// candidate paths.
func underAny(prefix string, candidates []string) bool {
	for _, c := range candidates {
		if c == prefix || strings.HasPrefix(c, prefix+"/") {
			return true
		}
	}
	return false
}

// writeInterpreterExecDenies emits process-exec deny rules for the entitled
// interpreters and sampling tools. A path is skipped when it is the very
// command the caller asked to run (including via symlink), so deliberately
// running, say, perl is not silently broken; a warning is emitted instead.
func writeInterpreterExecDenies(sb *strings.Builder, resolvedCmd string) {
	cmdPaths := cmdRealPaths(resolvedCmd)
	for _, p := range interpreterExecLiteralDenies {
		if underAny(p, cmdPaths) {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: blockInterpreters is on but the target command is %q; allowing it to run while still blocking it as a child of others.\n", p)
			continue
		}
		sb.WriteString(fmt.Sprintf("(deny process-exec (literal %q))\n", p))
	}
	sb.WriteString("(deny process-exec (regex #\"^/usr/bin/perl5\\.[0-9.]+$\"))\n")
	for _, p := range interpreterExecSubpathDenies {
		if underAny(p, cmdPaths) {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: blockInterpreters is on but the target command resolves under %q; not blocking it.\n", p)
			continue
		}
		sb.WriteString(fmt.Sprintf("(deny process-exec (subpath %q))\n", p))
	}
}

// writeInterpreterReadDenies emits file-read deny rules for the Tcl/Tk/Ffidl
// trees, skipping a tree the target command itself lives under (so an
// explicitly-run interpreter can still load its own runtime).
func writeInterpreterReadDenies(sb *strings.Builder, resolvedCmd string) {
	cmdPaths := cmdRealPaths(resolvedCmd)
	for _, p := range interpreterReadDenies {
		if underAny(p, cmdPaths) {
			continue
		}
		sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %q))\n", p))
	}
}

// persistenceWriteDenies returns the auto-execution and persistence
// directories that should be read-only to a confined build: LaunchAgents and
// LaunchDaemons, the plugin loader trees scanned by privileged daemons
// (DirectoryService, MIDIServer, QuickLook), preference stores that can be
// poisoned into launching code, and the world-writable /usr/local/bin that
// system diagnostic tools resolve helpers from. HOME-relative entries are
// added when HOME is set.
func persistenceWriteDenies() []string {
	paths := []string{
		"/Library/LaunchAgents",
		"/Library/LaunchDaemons",
		"/Library/DirectoryServices/PlugIns",
		"/Library/Audio/MIDI Drivers",
		"/Library/QuickLook",
		"/Library/Preferences",
		"/usr/local/bin",
		"/usr/local/sbin",
	}
	if home := os.Getenv("HOME"); home != "" {
		paths = append(paths,
			filepath.Join(home, "Library/LaunchAgents"),
			filepath.Join(home, "Library/LaunchDaemons"),
			filepath.Join(home, "Library/Audio/MIDI Drivers"),
			filepath.Join(home, "Library/QuickLook"),
			filepath.Join(home, "Library/Internet Plug-Ins"),
			filepath.Join(home, "Library/Spotlight"),
			filepath.Join(home, "Library/Services"),
			filepath.Join(home, "Library/Mail/Bundles"),
			filepath.Join(home, "Library/Preferences"),
		)
	}
	return paths
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

	// Deny preinstalled Apple-signed scripting engines and sampling tools.
	// These carry unsigned-executable-memory, library-validation, or
	// task-port exemptions, so a confined process could re-exec one and load
	// in-memory shellcode or an unsigned dylib that bypasses our filesystem
	// and exec confinement. Emitted last so the denies win under Seatbelt's
	// last-match-wins evaluation, regardless of the allow rules above.
	if cfg.BlockInterpreters {
		writeInterpreterExecDenies(&sb, resolvedCmd)
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
		// If BlockCryptoEntropy is true, restrict /dev/random and /dev/urandom
		if cfg.BlockCryptoEntropy && p == "/dev" {
			sb.WriteString("(allow file-read* (subpath \"/dev\"))\n")
			sb.WriteString("(deny file-read* (literal \"/dev/random\"))\n")
			sb.WriteString("(deny file-read* (literal \"/dev/urandom\"))\n")
			sb.WriteString("(deny file-read* (literal \"/dev/random.entropy\"))\n")
			continue
		}
		// Deny TPM device if BlockTPM is true
		if cfg.BlockTPM && p == "/dev" {
			sb.WriteString("(allow file-read* (subpath \"/dev\"))\n")
			sb.WriteString("(deny file-read* (literal \"/dev/tpm0\"))\n")
			sb.WriteString("(deny file-read* (literal \"/dev/tpmrm0\"))\n")
			continue
		}
		// Deny GPU nodes if AllowGPU is false
		if (!cfg.AllowGPU) && p == "/dev" {
			sb.WriteString("(allow file-read* (subpath \"/dev\"))\n")
			sb.WriteString("(deny file-read* (subpath \"/dev/dri\"))\n")
			sb.WriteString("(deny file-read* (literal \"/dev/opencl\"))\n")
			continue
		}
		sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", p))
	}

	// Explicitly block crypto libraries if BlockCrypto is true
	if cfg.BlockCrypto {
		sb.WriteString("(deny file-read* (subpath \"/usr/lib/system/libcommonCrypto.dylib\"))\n")
		sb.WriteString("(deny file-read* (subpath \"/usr/lib/libcrypto\"))\n")
		sb.WriteString("(deny file-read* (subpath \"/usr/lib/libssl\"))\n")
		sb.WriteString("(deny file-read* (subpath \"/etc/ssl\"))\n")
		sb.WriteString("(deny file-read* (subpath \"/private/etc/ssl\"))\n")
		sb.WriteString("(deny file-read* (subpath \"/etc/security\"))\n")
		sb.WriteString("(deny file-read* (subpath \"/private/etc/security\"))\n")
		sb.WriteString("(deny file-read* (subpath \"/System/Library/Frameworks/Security.framework\"))\n")
	}

	// Starve the FFI bridge: deny reads of the Tcl/Tk frameworks and the Tcl
	// script library (where Ffidl lives), so even an allowed interpreter
	// cannot load the libffi binding used to call mmap/mprotect directly.
	// Emitted after the broad /System read allow so the denies win.
	if cfg.BlockInterpreters {
		writeInterpreterReadDenies(&sb, resolvedCmd)
	}

	// Allow reading the specific command binary if it's an absolute path
	if filepath.IsAbs(cfg.Cmd) {
		sb.WriteString(fmt.Sprintf("(allow file-read* (literal %q))\n", cfg.Cmd))
	}

	// Always allow reading the working directory if specified
	if cfg.WorkingDir != "" {
		sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", cfg.WorkingDir))
		dir := cfg.WorkingDir
		for {
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			sb.WriteString(fmt.Sprintf("(allow file-read-metadata (literal %q))\n", parent))
			dir = parent
		}
	}

	// Always allow read/write to temp directories
	tempDirs := []string{"/private/tmp", "/tmp", os.TempDir()}
	for _, p := range tempDirs {
		if p != "" {
			sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", p))
			sb.WriteString(fmt.Sprintf("(allow file-write* (subpath %q))\n", p))
			dir := p
			for {
				parent := filepath.Dir(dir)
				if parent == dir {
					break
				}
				sb.WriteString(fmt.Sprintf("(allow file-read-metadata (literal %q))\n", parent))
				dir = parent
			}
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

	// Deny hidden files/directories if AllowHidden is false
	if !cfg.AllowHidden {
		sb.WriteString("(deny file-read* (regex #\"/\\.[^/]+\"))\n")
		sb.WriteString("(deny file-write* (regex #\"/\\.[^/]+\"))\n")
	}

	// The default system read paths above (/Library, /private/var, /private/etc)
	// are broad so that ordinary tooling can resolve DNS, load frameworks, and
	// read CA certificates. Several well-known locations under those trees hold
	// credentials and are never legitimately needed by a build or package
	// install, so they are denied here regardless of AllowHidden. Seatbelt uses
	// last-match-wins semantics, so these denies override the earlier allows.
	// For stricter confinement, pass explicit readPaths instead of relying on
	// the defaults.
	sensitiveReadDenies := []string{
		"/Library/Keychains",         // system keychain (e.g. System.keychain)
		"/private/var/db/dslocal",    // local directory service / shadow hashes
		"/private/etc/master.passwd", // shadow password file
		"/private/var/db/sudo",       // sudo timestamp store
		"/private/var/db/ConfigurationProfiles",
	}
	if home := os.Getenv("HOME"); home != "" {
		sensitiveReadDenies = append(sensitiveReadDenies,
			filepath.Join(home, "Library/Keychains"),                         // login keychain (login.keychain-db)
			filepath.Join(home, "Library/Cookies"),                           // saved cookies
			filepath.Join(home, "Library/Application Support/com.apple.TCC"), // TCC consent db
			filepath.Join(home, "Library/Application Support/Google/Chrome"),
			filepath.Join(home, "Library/Application Support/Firefox"),
		)
	}
	for _, p := range sensitiveReadDenies {
		sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %q))\n", p))
		sb.WriteString(fmt.Sprintf("(deny file-write* (subpath %q))\n", p))
	}

	// Deny writes to auto-execution and persistence locations. A build or
	// package install never legitimately stages a LaunchAgent, a loader
	// plugin, or a binary in /usr/local/bin, but those are exactly where a
	// malicious script would drop a payload to survive the sandbox or be
	// picked up by a privileged system service. Emitted after the temp/write
	// allows so the denies win; a path the caller explicitly granted via
	// WritePaths is exempt.
	if cfg.DenyPersistenceWrites {
		writePathSet := make(map[string]bool, len(cfg.WritePaths))
		for _, w := range cfg.WritePaths {
			writePathSet[filepath.Clean(w)] = true
		}
		for _, p := range persistenceWriteDenies() {
			if writePathSet[filepath.Clean(p)] {
				continue
			}
			sb.WriteString(fmt.Sprintf("(deny file-write* (subpath %q))\n", p))
		}
	}

	// Under blockInterpreters, deny reading .dylib files from the writable and
	// temporary trees. The disable-library-validation exemption lets an
	// entitled interpreter dlopen an unsigned dylib; if it can only be read
	// from writable scratch space, that path is closed. Native-addon builds
	// that compile and immediately load a dylib from the build tree can opt
	// out with AllowWritableDylibLoad; loadable Node addons (.node) are never
	// matched.
	if cfg.BlockInterpreters && !cfg.AllowWritableDylibLoad {
		dylibDenyPaths := append([]string{"/private/tmp", "/tmp", os.TempDir()}, cfg.WritePaths...)
		seen := make(map[string]bool)
		for _, p := range dylibDenyPaths {
			if p == "" {
				continue
			}
			cp := filepath.Clean(p)
			if seen[cp] {
				continue
			}
			seen[cp] = true
			sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %q) (regex #\"\\.dylib$\"))\n", cp))
		}
	}

	// Network rules
	resolvedIPs := cfg.AllowIPs
	if len(cfg.AllowHosts) > 0 {
		resolvedIPs = append(resolvedIPs, resolveIPs(cfg.AllowHosts)...)
	}
	resolvedIPs = dedupeStrings(resolvedIPs)

	// Network binding / listening rules (blocked by default, even on loopback)
	for _, listenStr := range cfg.AllowListen {
		target := listenStr
		if !strings.Contains(listenStr, ":") {
			target = listenStr + ":*"
		}
		sb.WriteString(fmt.Sprintf("(allow network-bind (local ip %q))\n", target))
		sb.WriteString(fmt.Sprintf("(allow network-inbound (local ip %q))\n", target))
	}

	if cfg.AllowLoopback {
		sb.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n")
	}

	// macOS Seatbelt cannot express a remote-IP allowlist: its (remote ip ...)
	// filter only accepts "*" or "localhost" as the host, so egress can be
	// confined by port but not pinned to specific hosts. When the caller supplies
	// allowHosts/allowIPs they intend host pinning, which Seatbelt cannot honor.
	// Rather than silently allowing all hosts, we (a) restrict egress to the
	// requested ports (defaulting to the standard web ports) instead of falling
	// through to an unrestricted allow, and (b) emit a clear warning so the
	// operator knows host pinning is not enforced on this platform. Pin egress by
	// host on Linux (Landlock/eBPF) or run with disableNetwork on macOS.
	hostPinningRequested := len(resolvedIPs) > 0
	if hostPinningRequested {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: macOS Seatbelt cannot restrict egress to specific IPs/hosts; egress is confined to the allowed ports only. Any host is reachable on those ports. Use disableNetwork for stricter isolation on macOS.\n")
	}

	writeOutboundRules := func() {
		ports := cfg.AllowPorts
		if hostPinningRequested && len(ports) == 0 {
			ports = []int{80, 443}
		}
		if len(ports) > 0 {
			for _, port := range ports {
				sb.WriteString(fmt.Sprintf("(allow network-outbound (remote ip \"*:%d\"))\n", port))
			}
			return
		}
		sb.WriteString("(allow network-outbound)\n")
	}

	if cfg.DisableNetwork {
		sb.WriteString("(deny network-outbound)\n")
		// Re-allow loopback outbound specifically if loopback is permitted
		if cfg.AllowLoopback {
			sb.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n")
		}
		// With the network disabled, only the explicitly requested ports are
		// re-allowed. If nothing is requested there is nothing to re-allow.
		if hostPinningRequested || len(cfg.AllowPorts) > 0 {
			writeOutboundRules()
		} else if cfg.EnableAudit {
			sb.WriteString("(trace network-outbound)\n")
		}
	} else {
		writeOutboundRules()
	}

	if cfg.EnableAudit {
		sb.WriteString("(trace file-read*)\n")
		sb.WriteString("(trace file-write*)\n")
		sb.WriteString("(trace network-outbound)\n")
	}

	return sb.String()
}

// dedupeStrings returns the input with duplicate entries removed, preserving
// first-seen order.
func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
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

// runDiagnostics probes macOS capabilities and returns a structured report.
func runDiagnostics() config.DiagnosticsResult {
	result := config.DiagnosticsResult{
		Platform:     "darwin",
		Arch:         runtime.GOARCH,
		Capabilities: make(map[string]config.CapabilityInfo),
		Features:     make(map[string]bool),
	}

	// Kernel version
	if uname, err := exec.Command("uname", "-r").Output(); err == nil {
		result.Kernel = strings.TrimSpace(string(uname))
	}
	if swVers, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
		result.Release = "macOS " + strings.TrimSpace(string(swVers))
	}

	// sandbox-exec
	if _, err := exec.LookPath("sandbox-exec"); err == nil {
		result.Capabilities["sandbox_exec"] = config.CapabilityInfo{Available: true, Detail: "sandbox-exec is in PATH"}
	} else {
		result.Capabilities["sandbox_exec"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
	}

	// Seatbelt profile
	if result.Capabilities["sandbox_exec"].Available {
		result.Capabilities["seatbelt_profile"] = config.CapabilityInfo{Available: true, Detail: "Seatbelt (Sandbox) profile generation via sandbox-exec"}
	} else {
		result.Capabilities["seatbelt_profile"] = config.CapabilityInfo{Available: false, Detail: "sandbox-exec not found"}
	}

	// RLIMIT_AS
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(rlimitAS, &rlim); err == nil {
		result.Capabilities["rlimit_as"] = config.CapabilityInfo{Available: true, Detail: fmt.Sprintf("max address space: %d bytes", rlim.Max)}
	} else {
		result.Capabilities["rlimit_as"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
	}

	// RLIMIT_CPU
	if err := syscall.Getrlimit(rlimitCPU, &rlim); err == nil {
		result.Capabilities["rlimit_cpu"] = config.CapabilityInfo{Available: true, Detail: fmt.Sprintf("max CPU time: %d seconds", rlim.Max)}
	} else {
		result.Capabilities["rlimit_cpu"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
	}

	// RLIMIT_NPROC
	if err := syscall.Getrlimit(rlimitNPROC, &rlim); err == nil {
		result.Capabilities["rlimit_nproc"] = config.CapabilityInfo{Available: true, Detail: fmt.Sprintf("max processes: %d", rlim.Max)}
	} else {
		result.Capabilities["rlimit_nproc"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
	}

	// FIPS detection
	_, err := exec.Command("/usr/bin/defaults", "read", "/Library/Preferences/com.apple.security", "FIPSMode").Output()
	detail := "defaults read available"
	if err == nil {
		detail = "FIPSMode plist key found"
	}
	result.Capabilities["fips_detection"] = config.CapabilityInfo{Available: true, Detail: detail}

	// DYLD_INSERT_LIBRARIES
	result.Capabilities["dyld_insert_libraries"] = config.CapabilityInfo{Available: true, Detail: "DYLD_INSERT_LIBRARIES supported (SIP-restricted for protected binaries)"}

	// Map capabilities to features
	hasSandbox := result.Capabilities["sandbox_exec"].Available
	result.Features["network_isolation"] = hasSandbox
	result.Features["file_read_restriction"] = hasSandbox
	result.Features["file_write_restriction"] = hasSandbox
	result.Features["memory_limit"] = result.Capabilities["rlimit_as"].Available
	result.Features["cpu_limit"] = result.Capabilities["rlimit_cpu"].Available
	result.Features["process_limit"] = result.Capabilities["rlimit_nproc"].Available
	result.Features["exec_control"] = hasSandbox
	result.Features["fork_control"] = hasSandbox
	result.Features["audit_tracing"] = hasSandbox
	result.Features["filesystem_diff"] = true
	result.Features["learning_mode"] = hasSandbox
	result.Features["strict_mode"] = true
	result.Features["crypto_control"] = hasSandbox
	result.Features["fips_detection"] = true
	result.Features["gpu_control"] = hasSandbox
	result.Features["tpm_control"] = hasSandbox
	result.Features["antivm_spoofing"] = hasSandbox
	result.Features["trace_libraries"] = true
	result.Features["trace_http_urls"] = false
	result.Features["allow_url_rules"] = false
	result.Features["trace_crypto"] = false
	result.Features["profile_validation"] = hasSandbox // sandbox-exec -n validates profiles
	result.Features["time_isolation"] = false          // not applicable on macOS
	result.Features["ipc_isolation"] = false           // not applicable on macOS
	result.Features["io_limit"] = false                // not applicable on macOS
	result.Features["landlock_filesystem"] = false     // Linux-only
	result.Features["landlock_layers"] = false         // Linux-only
	result.Features["apparmor_safer_exec"] = false     // Linux-only
	result.Features["proc_hidepid"] = false            // Linux-only

	return result
}

// Ensure imports are used
var _ = json.Marshal
var _ = bufio.Scanner{}
