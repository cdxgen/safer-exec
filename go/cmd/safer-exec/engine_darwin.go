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
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
		profile := buildSeatbeltProfile(cfg, 0)
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

	// Egress proxy: enforce the hostname allowlist at CONNECT time and confine
	// all outbound traffic to the loopback proxy port. This is the only way to
	// get hostname-level egress control on macOS (Seatbelt is port-only).
	// Must run before BuildEnv so the injected HTTP(S)_PROXY variables reach
	// the sandboxed process.
	var proxy *egressProxy
	proxyPort := 0
	if cfg.ProxyEgress {
		if p, err := startEgressProxy(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: egress proxy unavailable (%v); falling back to port-only egress confinement\n", err)
		} else {
			proxy = p
			defer p.Close()
			proxyPort = p.port
			p.injectEnv(&cfg)
			// The sandboxed process must be able to reach 127.0.0.1:proxyPort.
			cfg.AllowLoopback = true
			fmt.Fprintf(os.Stderr, "safer-exec: egress proxy listening on 127.0.0.1:%d; outbound traffic is confined to it and hostnames are enforced at CONNECT time\n", proxyPort)
		}
	}

	// Set environment securely using filtered environment (includes any proxy
	// variables injected above)
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
	profile := buildSeatbeltProfile(cfg, proxyPort)

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

	auditStartedAt := time.Now()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("running command: %w", err)
	}
	// The sandboxed target keeps the sandbox-exec PID (the profile is applied
	// and the command exec'd in place), used later for audit attribution.
	rootPID := cmd.Process.Pid

	waitDone := func() error { return cmd.Wait() }

	// os.Exit skips deferred cleanup, so proxy teardown and audit flushes are
	// funneled through here on every exit path.
	finish := func() {
		if proxy != nil {
			proxy.flushViolations()
			proxy.Close()
			proxy = nil
		}
		reportDarwinAudit(cfg, auditStartedAt, rootPID)
	}

	// Set a hard timeout using a goroutine if timeoutMs is set
	if cfg.TimeoutMs > 0 {
		done := make(chan error, 1)
		go func() {
			done <- waitDone()
		}()

		select {
		case err := <-done:
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					code := exitErr.ExitCode()
					finish()
					if code == 132 || code == 137 || code == 153 {
						os.Exit(0)
					}
					os.Exit(code)
				}
				finish()
				return fmt.Errorf("running command: %w", err)
			}
		case <-time.After(time.Duration(cfg.TimeoutMs) * time.Millisecond):
			cmd.Process.Kill()
			<-done
			finish()
			os.Exit(124) // Standard timeout exit code
		}
	} else {
		if err := waitDone(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				code := exitErr.ExitCode()
				finish()
				if code == 132 || code == 137 || code == 153 {
					os.Exit(0)
				}
				os.Exit(code)
			}
			finish()
			return fmt.Errorf("running command: %w", err)
		}
	}
	finish()

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

// reportDarwinAudit emits Seatbelt violations recorded during the run as JSON
// audit lines on stderr (the protocol the Node runner parses with
// parseAuditLog: one {"type","target","details"} object per line, matching
// the Linux engine's logAuditEntry shape). macOS reports sandbox denials to
// the unified log rather than a pipe, so they are read back with
// /usr/bin/log show after the sandboxed process has exited. Best effort: on
// failure a warning is printed and the run result stands.
func reportDarwinAudit(cfg config.ExecConfig, startedAt time.Time, rootPID int) {
	if !cfg.EnableAudit {
		return
	}
	events := collectSandboxViolations(startedAt, rootPID)
	const maxAuditEntries = 1000
	if len(events) > maxAuditEntries {
		events = events[:maxAuditEntries]
	}
	for _, ev := range events {
		target := ev.Path
		if target == "" {
			target = ev.Target
		}
		if ev.Port != 0 {
			target = fmt.Sprintf("%s:%d", ev.Target, ev.Port)
		}
		if target == "" {
			continue
		}
		entry := map[string]string{
			"type":    ev.Type,
			"target":  target,
			"details": fmt.Sprintf("violation detected at %s", target),
		}
		if data, err := json.Marshal(entry); err == nil {
			fmt.Fprintf(os.Stderr, "%s\n", string(data))
		}
	}
}

// runValidateProfile validates the generated Seatbelt profile using sandbox-exec -n.
// This syntax-checks the profile without executing the command, reporting any errors.
func runValidateProfile(cfg config.ExecConfig) error {
	profile := buildSeatbeltProfile(cfg, 0)

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

	// Preserve the hardening/isolation flags this run was configured with so
	// the learned policy can be re-applied without silently dropping them.
	policy = config.OverlayExecConfigToPolicy(cfg, policy)

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
// via Seatbelt while system bootstrap paths stay readable so the binary can
// start and walk its control flow. Denied operations are reported by the
// kernel to the unified log (sandboxd / "Sandbox: proc(pid) deny ..." lines),
// which we collect via /usr/bin/log show after the run and turn into the
// DRYRUN report. The sandboxed process tree keeps the sandbox-exec PID and
// its descendants use higher PIDs, so attribution is "event pid >= root pid".
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

	startedAt := time.Now()

	// Run under sandbox-exec with the dry-run profile
	fullArgs := append([]string{"-f", profFile.Name(), cmdPath}, cfg.Args...)
	cmd := exec.Command("sandbox-exec", fullArgs...)
	cmd.Env = config.BuildEnv(cfg.Env)
	if cfg.WorkingDir != "" {
		cmd.Dir = cfg.WorkingDir
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting dry-run: %w", err)
	}
	// sandbox-exec applies the profile and execs the target in-place, so the
	// target keeps this PID; every descendant gets a higher PID.
	rootPID := cmd.Process.Pid
	_ = cmd.Wait() // ignore real exit code

	events := collectSandboxViolations(startedAt, rootPID)
	result := buildDryRunResult(events, cfg.Cmd, cfg.Args)

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

	// Root-directory reads and metadata lookups happen during bootstrap path
	// resolution for every process. Without these allows the target aborts on
	// its first denied lookup (deny kills via SIGABRT before the program even
	// starts), which would reduce the whole report to bootstrap noise.
	sb.WriteString("(allow file-read-data (literal \"/\"))\n")
	sb.WriteString("(allow file-read-metadata)\n")

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

// sandboxEventLine matches unified-log sandbox reports of the form
//
//	kernel[0:t] (Sandbox) Sandbox: cat(40289) deny(1) file-read-data /path
//
// capturing process name, pid, decision, operation, and the remainder
// (operation argument). Duplicate-report aggregation lines
// ("N duplicate reports for Sandbox: ...") do not match because they put the
// report count before "Sandbox:".
var sandboxEventLine = regexp.MustCompile(`Sandbox: ([^\s(]+)\((\d+)\) (allow|deny)(?:\(\d+\))? (\S+)(?: (.*))?$`)

// collectSandboxViolations reads Seatbelt deny reports for processes at or
// after rootPID from the unified log. Seatbelt violations are emitted by the
// kernel (sender "Sandbox") and aggregated by sandboxd; both forms are
// covered by matching on the "Sandbox: ..." message text. The log subsystem
// flushes asynchronously, so the query is retried once after a short delay
// when the first attempt returns nothing.
func collectSandboxViolations(since time.Time, rootPID int) []config.DryRunEvent {
	var events []config.DryRunEvent
	for attempt := 0; attempt < 2; attempt++ {
		events = querySandboxLog(since, rootPID)
		if len(events) > 0 {
			return events
		}
		time.Sleep(1200 * time.Millisecond)
	}
	return events
}

// querySandboxLog runs `/usr/bin/log show` for the window starting at since
// and converts matching deny lines into DryRunEvents attributed to the
// sandboxed tree (pid >= rootPID; PIDs are handed out in increasing order, so
// pre-existing noisy processes that started earlier sort themselves out).
func querySandboxLog(since time.Time, rootPID int) []config.DryRunEvent {
	cmd := exec.Command("/usr/bin/log", "show",
		"--start", since.Format("2006-01-02 15:04:05"),
		"--debug", "--info",
		"--predicate", `eventMessage BEGINSWITH "Sandbox" OR eventMessage CONTAINS "for Sandbox:"`,
		"--style", "compact")
	out, err := cmd.Output()
	if err != nil {
		// log show may be unavailable or slow on some systems; dry-run still
		// succeeds, just without the event report.
		fmt.Fprintf(os.Stderr, "safer-exec: warning: reading unified log for sandbox events: %v\n", err)
		return nil
	}

	var events []config.DryRunEvent
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		pid, ev := sandboxEventFromLine(scanner.Text())
		if ev == nil || pid < rootPID {
			continue
		}
		events = append(events, *ev)
	}
	return events
}

// sandboxEventFromLine converts one unified-log line into the reporting PID
// and its deny event (nil when the line is not a reportable violation —
// allow lines, duplicate-report aggregation, and noisy op classes).
func sandboxEventFromLine(line string) (int, *config.DryRunEvent) {
	if strings.Contains(line, "duplicate report") {
		return 0, nil
	}
	m := sandboxEventLine.FindStringSubmatch(line)
	if m == nil {
		return 0, nil
	}
	if m[3] != "deny" {
		return 0, nil
	}
	pid, _ := strconv.Atoi(m[2])
	return pid, sandboxOpToEvent(m[4], m[5])
}

// sandboxOpToEvent converts a Seatbelt operation + argument into a
// DryRunEvent. Noisy bootstrap classes (mach-lookup, sysctl-read,
// user-preference-read, ipc-*, iokit-*, system-socket) are dropped: they
// flood the report and are not actionable for supply-chain auditing.
func sandboxOpToEvent(op, arg string) *config.DryRunEvent {
	var event config.DryRunEvent
	switch {
	case op == "network-outbound":
		event.Type = "network-outbound"
		parseNetworkArg(arg, &event)
		return &event
	case op == "network-bind" || op == "network-inbound":
		event.Type = "network-bind"
		parseNetworkArg(arg, &event)
		return &event
	case op == "process-exec":
		event.Type = "process-exec"
		event.Path = strings.TrimSpace(arg)
		return &event
	case op == "process-fork":
		event.Type = "process-fork"
		return &event
	case strings.HasPrefix(op, "file-read-metadata") || op == "file-read-meta":
		event.Type = "file-metadata"
		event.Path = strings.TrimSpace(arg)
		return &event
	case strings.HasPrefix(op, "file-read"):
		event.Type = "file-read"
		event.Path = strings.TrimSpace(arg)
		return &event
	case strings.HasPrefix(op, "file-write"):
		event.Type = "file-write"
		event.Path = strings.TrimSpace(arg)
		return &event
	default:
		return nil
	}
}

// parseNetworkArg fills Target/Port from a Seatbelt network argument. TCP
// denials look like "remote:IP:PORT" (or remote:*:port when a port-wide rule
// denied the connect); Unix-socket denials carry a plain filesystem path.
func parseNetworkArg(arg string, event *config.DryRunEvent) {
	arg = strings.TrimSpace(arg)
	if rest, ok := strings.CutPrefix(arg, "remote:"); ok {
		host, port, err := net.SplitHostPort(rest)
		if err != nil {
			event.Target = rest
			return
		}
		event.Target = host
		event.Port, _ = strconv.Atoi(port)
		return
	}
	event.Target = arg
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
// proxyPort is the loopback port of the egress proxy when ProxyEgress is
// active, 0 otherwise.
func buildSeatbeltProfile(cfg config.ExecConfig, proxyPort int) string {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n")
	sb.WriteString("(import \"system.sb\")\n")
	sb.WriteString("(allow signal)\n")

	// Trust and network-configuration services. TLS stacks that use the
	// Security framework instead of reading certificate files directly
	// (e.g. anything going through SecTrust) evaluate the system trust store
	// via mach-lookup to trustd, and read proxy/interface configuration via
	// configd. Without these allows, HTTPS from such runtimes fails with
	// "bad certificate format". Both are read-only evaluation services: they
	// expose no user secrets and no code execution.
	sb.WriteString(`(allow mach-lookup (global-name "com.apple.trustd"))` + "\n")
	sb.WriteString(`(allow mach-lookup (global-name "com.apple.trustd.agent"))` + "\n")
	sb.WriteString(`(allow mach-lookup (global-name "com.apple.SystemConfiguration.configd"))` + "\n")

	// securityd and the user-database services stay OUT of the baseline.
	// com.apple.SecurityServer is the keychain endpoint — reachable securityd
	// means a sandboxed build script can ask an unlocked login keychain for
	// items whose ACL does not force a prompt. opendirectoryd/memberd expose
	// the user and group database. Certificate validation does not need any
	// of them (that is trustd, allowed above), so they are opt-in: .NET is
	// the known case, since its SslStream path talks to securityd and it
	// resolves the home directory through getpwuid() rather than $HOME.
	if cfg.AllowSecurityServices {
		sb.WriteString(`(allow mach-lookup (global-name "com.apple.SecurityServer"))` + "\n")
		sb.WriteString(`(allow mach-lookup (global-name "com.apple.system.opendirectoryd"))` + "\n")
		sb.WriteString(`(allow mach-lookup (global-name "com.apple.memberd"))` + "\n")
	}

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
	//
	// IMPORTANT: on current macOS the (subpath X) + (regex Y) combination does
	// NOT conjoin — the regex alone matches system-wide, so a bare `\.dylib$`
	// regex would deny loading every non-cached dylib on the host (dotnet's
	// libhostfxr, Homebrew libraries, ...). Each deny therefore uses a single
	// regex anchored to ^<tree>/ … \.dylib$.
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
			sb.WriteString(fmt.Sprintf("(deny file-read* (regex #\"^%s/.*\\.dylib$\"))\n", regexp.QuoteMeta(cp)))
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

	if cfg.AllowLoopback && proxyPort == 0 {
		sb.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n")
	}

	// Egress proxy mode: ALL outbound traffic is forced through the loopback
	// proxy, which enforces the hostname allowlist at CONNECT time. This is
	// the only hostname-level egress control available on macOS — Seatbelt
	// cannot pin remote IPs. Everything not explicitly allowed below stays
	// denied by (deny default).
	if proxyPort > 0 {
		sb.WriteString(fmt.Sprintf("(allow network-outbound (remote ip \"localhost:%d\"))\n", proxyPort))
		// DNS to the system resolver is a unix-socket connection, not TCP;
		// keep it working so local name resolution inside the sandbox is
		// unaffected (target hostnames are resolved by the proxy in the
		// parent anyway).
		sb.WriteString("(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n")
		if cfg.EnableAudit {
			sb.WriteString("(trace network-outbound)\n")
		}
		if cfg.EnableAudit {
			sb.WriteString("(trace file-read*)\n")
			sb.WriteString("(trace file-write*)\n")
		}
		return sb.String()
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
		// DNS resolution on macOS connects to the system resolver over a
		// unix socket, not TCP — without this allow every getaddrinfo fails
		// (curl exit 6, dotnet NU1301) even when the target ports are open.
		// The lookup itself is name resolution, not egress to an arbitrary
		// host; the resolved destination is still gated by the port rules.
		sb.WriteString("(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n")
		if len(ports) > 0 {
			for _, port := range ports {
				sb.WriteString(fmt.Sprintf("(allow network-outbound (remote ip \"*:%d\"))\n", port))
			}
			return
		}
		sb.WriteString("(allow network-outbound)\n")
	}

	if cfg.DisableNetwork {
		// disableNetwork is absolute: nothing is re-allowed except loopback
		// when explicitly requested. (Previously the requested ports were
		// re-allowed when host pinning was set, but Seatbelt cannot pin IPs,
		// so that made every host reachable on those ports — the opposite of
		// disabling the network. It only looked correct because DNS was
		// itself broken.) Linux semantics (a fresh network namespace) match.
		sb.WriteString("(deny network-outbound)\n")
		if cfg.AllowLoopback {
			sb.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n")
		}
		if cfg.EnableAudit {
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
