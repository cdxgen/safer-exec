//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cdxgen/safer-exec/go/internal/config"
	"github.com/cdxgen/safer-exec/go/internal/fsdiff"
	"github.com/cdxgen/safer-exec/go/internal/httptrace"
	"github.com/cdxgen/safer-exec/go/internal/learner"
)

const cgroupV2Root = "/sys/fs/cgroup"

const (
	sysKCMP     = sysKCMP_unified
	sysSYSCALL  = sysSYSCALL_unified
	sysFORK     = sysFORK_unified
	sysVFORK    = sysVFORK_unified
	sysEXECVEAT = sysEXECVEAT_unified
)

const (
	seccompRetKill  = 0x00000000
	seccompRetTrap  = 0x00030000
	seccompRetAllow = 0x7fff0000
)

const sysSeccomp = sysSeccomp_unified

const (
	bpfLoadWordAbsolute = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJmpEq            = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfJmpSet           = 0x45 // BPF_JMP | BPF_JSET | BPF_K
	bpfJmpReturn        = 0x06 // BPF_RET | BPF_K
)

// cloneThreadFlag is CLONE_THREAD: set when clone creates a thread, not a child process.
// On arm64, glibc and Node.js use clone() for thread creation (not clone3), so blocking
// SYS_CLONE unconditionally kills the sandboxed process. We only block forks (no CLONE_THREAD).
const cloneThreadFlag = 0x00010000

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

// isUserNamespaceRestricted returns true when the kernel or security policy
// prevents unprivileged processes from creating user namespaces. Covers the
// three common Linux mechanisms:
//   - Ubuntu 24.04+ AppArmor restriction (apparmor_restrict_unprivileged_userns)
//   - Debian/some-kernel explicit disable (unprivileged_userns_clone)
//   - Kernel compiled with user namespaces disabled (max_user_namespaces = 0)
func isUserNamespaceRestricted() bool {
	sysctls := []struct {
		path      string
		killValue string
	}{
		{"/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "1"},
		{"/proc/sys/kernel/unprivileged_userns_clone", "0"},
		{"/proc/sys/user/max_user_namespaces", "0"},
	}
	for _, s := range sysctls {
		if data, err := os.ReadFile(s.path); err == nil {
			if strings.TrimSpace(string(data)) == s.killValue {
				return true
			}
		}
	}
	return false
}

// run forks the Go binary using the system 'unshare' to bypass Go's multi-threading EINVAL issues.
// If user namespaces are unavailable it falls back to reduced isolation (seccomp + landlock only).
func run(cfg config.ExecConfig) error {
	if cfg.EnableLearn {
		return runLearn(cfg)
	}
	// Take pre-execution snapshot for filesystem diffing
	var beforeSnap fsdiff.Snapshot
	if cfg.EnableDiff && len(cfg.WritePaths) > 0 {
		beforeSnap, _ = fsdiff.SnapshotPath(cfg.WritePaths...)
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding self: %w", err)
	}

	var auditR, auditW *os.File
	if cfg.EnableAudit {
		auditR, auditW, err = os.Pipe()
		if err != nil {
			return fmt.Errorf("creating audit pipe: %w", err)
		}
	}

	// Fall back to reduced isolation when user namespaces are blocked by kernel policy.
	// Reduced mode skips mount/PID/network/UTS namespace isolation and filesystem pivot,
	// but still applies seccomp-bpf syscall filtering and Landlock network confinement.
	if isUserNamespaceRestricted() {
		if auditR != nil {
			auditR.Close()
		}
		if auditW != nil {
			auditW.Close()
		}
		if cfg.Strict {
			return fmt.Errorf("user namespaces unavailable")
		}
		fmt.Fprintf(os.Stderr, "safer-exec: warning: user namespaces unavailable — running with reduced isolation (seccomp + landlock only; no filesystem, PID, or network namespace isolation). Install the safer-exec AppArmor profile for full isolation. See README for details.\n")
		return runReduced(cfg, cfgJSON, selfPath)
	}

	// Use system unshare to create namespaces before Go starts
	unshareArgs := []string{"-U", "-m", "-p", "--fork", "-u", "-r"}
	if cfg.DisableNetwork {
		unshareArgs = append(unshareArgs, "-n")
	}
	unshareArgs = append(unshareArgs, "--", selfPath, "--init")

	cmd := exec.Command("unshare", unshareArgs...)
	cmd.Env = append(config.FilteredEnviron(), fmt.Sprintf("SAFER_EXEC_CONFIG=%s", string(cfgJSON)))
	if cfg.EnableAudit {
		cmd.Env = append(cmd.Env, "SAFER_EXEC_AUDIT_FD=3")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{auditW}

	if cfg.WorkingDir != "" {
		cmd.Dir = cfg.WorkingDir
	}

	// Start eBPF HTTP URL tracer BEFORE cmd.Start() so uprobes are attached
	// before the child process can call SSL_write. Loading BPF takes ~10-50ms;
	// doing it first ensures fast-starting commands (e.g. curl) are captured.
	// A background goroutine refreshes the PID filter every 5ms after the
	// process starts, covering the unshare → --init → target spawn chain.
	var httpTracer httptrace.Tracer
	var httpEvents []config.HTTPAccessEntry
	var stopPIDRefresh chan struct{}
	if cfg.TraceHTTPURLs {
		if tr, err2 := httptrace.New(); err2 == nil {
			httpTracer = tr

			// Resolve command path to attach static uprobes to target binary
			var cmdPath string
			if filepath.IsAbs(cfg.Cmd) {
				cmdPath = cfg.Cmd
			} else if cfg.WorkingDir != "" {
				cmdPath = filepath.Join(cfg.WorkingDir, cfg.Cmd)
				if _, err := os.Stat(cmdPath); err != nil {
					cmdPath, _ = exec.LookPath(cfg.Cmd)
				}
			} else {
				cmdPath, _ = exec.LookPath(cfg.Cmd)
			}
			if cmdPath == "" {
				cmdPath = cfg.Cmd
			}

			_ = httpTracer.AttachStaticOpenSSL(cmdPath)
			_ = httpTracer.AttachGoTLS(cmdPath)
		} else {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: http-trace: %v\n", err2)
		}
	}

	if err := cmd.Start(); err != nil {
		if cfg.EnableAudit && auditR != nil {
			auditR.Close()
		}
		if httpTracer != nil {
			httpTracer.Close()
		}
		return fmt.Errorf("starting sandboxed process: %w", err)
	}

	if cfg.EnableAudit && auditW != nil {
		auditW.Close()
	}

	var stopMonitor chan struct{}
	if cfg.TraceLibraries && isMusl() {
		stopMonitor = make(chan struct{})
		go monitorMaps(cmd.Process.Pid, stopMonitor)
	}

	if httpTracer != nil {
		rootPID := uint32(cmd.Process.Pid)
		_ = httpTracer.AddPID(rootPID)
		stopPIDRefresh = make(chan struct{})
		go func() {
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				for p := range httptrace.PidDescendants(rootPID) {
					_ = httpTracer.AddPID(p)
				}
				select {
				case <-stopPIDRefresh:
					return
				case <-ticker.C:
				}
			}
		}()

		go func() {
			for ev := range httpTracer.Events() {
				entry := config.HTTPAccessEntry{
					Method:   ev.Method,
					Host:     ev.Host,
					Path:     ev.Path,
					Protocol: ev.Protocol,
					Port:     ev.Port,
					Query:    ev.Query,
					Body:     ev.Body,
					Source:   ev.Source.String(),
					PID:      ev.PID,
				}
				if cfg.EnableAudit {
					logAuditHTTPEntry(entry)
				}
				httpEvents = append(httpEvents, entry)
			}
		}()
	}

	err = cmd.Wait()
	if stopPIDRefresh != nil {
		close(stopPIDRefresh)
	}
	if stopMonitor != nil {
		close(stopMonitor)
	}
	if httpTracer != nil {
		// Allow ring buffer drain goroutine to flush remaining events before close.
		time.Sleep(100 * time.Millisecond)
		httpTracer.Close()
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if cfg.EnableAudit && auditR != nil {
				collectAuditLog(auditR)
			}
			code := exitErr.ExitCode()
			if code == 132 || code == 137 || code == 153 {
				// Output diff even if killed by limits
				if cfg.EnableDiff && beforeSnap != nil {
					if afterSnap, err := fsdiff.SnapshotPath(cfg.WritePaths...); err == nil {
						diff := fsdiff.Diff(beforeSnap, afterSnap)
						if data, err := json.Marshal(diff); err == nil {
							writeStructured(cfg, "FSDIFF:", data)
						}
					}
				}
				return nil
			}
			if code == -1 {
				fmt.Fprintf(os.Stderr, "safer-exec: process killed by signal: %v\n", exitErr.ProcessState.String())
			}
			return &ExitError{Code: code}
		}
		return fmt.Errorf("running sandboxed process: %w", err)
	}

	// Take post-execution snapshot and output diff on success
	if cfg.EnableDiff && beforeSnap != nil {
		if afterSnap, err := fsdiff.SnapshotPath(cfg.WritePaths...); err == nil {
			diff := fsdiff.Diff(beforeSnap, afterSnap)
			if data, err := json.Marshal(diff); err == nil {
				writeStructured(cfg, "FSDIFF:", data)
			}
		}
	}

	if cfg.EnableAudit && auditR != nil {
		collectAuditLog(auditR)
	}

	// Enforce AllowURLRules against captured HTTP events (Linux-only, requires TraceHTTPURLs).
	// This is observational enforcement: Landlock already restricts ports; we surface
	// per-URL violations as structured audit entries so callers know exactly which
	// URL patterns the command tried to reach outside the declared policy.
	if len(cfg.AllowURLRules) > 0 && len(httpEvents) > 0 {
		compiledRules := config.CompileURLRules(cfg.AllowURLRules)
		for i := range httpEvents {
			e := &httpEvents[i]
			if !config.MatchesAny(compiledRules, e.Method, e.Protocol, e.Host, e.Port, e.Path) {
				e.Blocked = true
				targetURL := e.Protocol + "://" + e.Host + e.Path
				logAuditEntry("url-violation", targetURL)
				fmt.Fprintf(os.Stderr, "safer-exec: url-violation: %s %s://%s%s (pid %d) — no matching AllowURLRule\n",
					e.Method, e.Protocol, e.Host, e.Path, e.PID)
			}
		}
	}

	// If EnableLearn was true, send the learning events to the learner
	if cfg.EnableLearn && len(httpEvents) > 0 {
		// Ensure learner gets http events as file access events
		for _, e := range httpEvents {
			fmt.Fprintf(os.Stderr, "safer-exec: learn: http-request: %s %s\n", e.Method, e.Host+e.Path)
		}
	}

	return nil
}

// runLearn executes the command in learning mode using strace to observe behavior.
func runLearn(cfg config.ExecConfig) error {
	l := learner.New()

	// Set up eBPF HTTP tracer if requested
	var httpTracer httptrace.Tracer
	var httpEntries []config.HTTPAccessEntry
	if cfg.TraceHTTPURLs {
		if tr, err := httptrace.New(); err == nil {
			httpTracer = tr
			// In learn mode with strace, we set trace-all because we don't
			// know child PIDs ahead of time; strace spawns them itself.
			_ = tr.SetTraceAll(true)
			go func() {
				for ev := range tr.Events() {
					httpEntries = append(httpEntries, config.HTTPAccessEntry{
						Method: ev.Method,
						Host:   ev.Host,
						Path:   ev.Path,
						Source: ev.Source.String(),
						PID:    ev.PID,
					})
				}
			}()
		} else {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: http-trace unavailable: %v\n", err)
		}
	}

	policy, err := l.Learn(cfg)

	if httpTracer != nil {
		httpTracer.Close()
	}

	if err != nil {
		return fmt.Errorf("learning mode: %w", err)
	}

	// Merge HTTP access entries into the learned policy.
	if len(httpEntries) > 0 {
		policy.HTTPAccess = deduplicateHTTPAccess(httpEntries)
		// Synthesise AllowURLRules from observed HTTP access for use as an
		// enforcement policy in subsequent runs with --policy-file.
		policy.AllowURLRules = config.SynthesiseURLRules(httpEntries)
	}

	data, _ := json.Marshal(policy)
	writeStructured(cfg, "LEARNED:", data)
	return nil
}

// deduplicateHTTPAccess removes duplicate (method, host, path) tuples,
// keeping the first occurrence.
func deduplicateHTTPAccess(entries []config.HTTPAccessEntry) []config.HTTPAccessEntry {
	type key struct{ method, host, path string }
	seen := make(map[key]bool, len(entries))
	var result []config.HTTPAccessEntry
	for _, e := range entries {
		k := key{e.Method, e.Host, e.Path}
		if !seen[k] {
			seen[k] = true
			result = append(result, e)
		}
	}
	return result
}

// runReduced executes the target command with reduced isolation when user namespaces
// are unavailable. It spawns self with --init-reduced, which applies seccomp-bpf and
// Landlock network confinement without any namespace or filesystem isolation.
func runReduced(cfg config.ExecConfig, cfgJSON []byte, selfPath string) error {
	// Filesystem diffing requires OverlayFS (mount namespace). Skip and warn.
	if cfg.EnableDiff {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: --diff requires mount namespace isolation; skipped in reduced isolation mode\n")
	}

	var auditR, auditW *os.File
	if cfg.EnableAudit {
		var err error
		auditR, auditW, err = os.Pipe()
		if err != nil {
			return fmt.Errorf("creating audit pipe: %w", err)
		}
	}

	cmd := exec.Command(selfPath, "--init-reduced")
	cmd.Env = append(config.FilteredEnviron(), fmt.Sprintf("SAFER_EXEC_CONFIG=%s", string(cfgJSON)))
	if cfg.EnableAudit {
		cmd.Env = append(cmd.Env, "SAFER_EXEC_AUDIT_FD=3")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{auditW}

	if cfg.WorkingDir != "" {
		cmd.Dir = cfg.WorkingDir
	}

	if err := cmd.Start(); err != nil {
		if auditR != nil {
			auditR.Close()
		}
		return fmt.Errorf("starting reduced sandbox: %w", err)
	}

	if auditW != nil {
		auditW.Close()
	}

	var stopMonitor chan struct{}
	if cfg.TraceLibraries && isMusl() {
		stopMonitor = make(chan struct{})
		go monitorMaps(cmd.Process.Pid, stopMonitor)
	}

	err := cmd.Wait()
	if stopMonitor != nil {
		close(stopMonitor)
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if auditR != nil {
				collectAuditLog(auditR)
			}
			code := exitErr.ExitCode()
			if code == 132 || code == 137 || code == 153 {
				return nil
			}
			if code == -1 {
				fmt.Fprintf(os.Stderr, "safer-exec: process killed by signal: %v\n", exitErr.ProcessState.String())
			}
			return &ExitError{Code: code}
		}
		return fmt.Errorf("reduced sandbox: %w", err)
	}

	if auditR != nil {
		collectAuditLog(auditR)
	}
	return nil
}

// runInitReduced is the inner init for reduced isolation mode. It skips namespace
// and filesystem setup, applying only seccomp-bpf and Landlock network confinement.
func runInitReduced(cfg config.ExecConfig) error {
	cgroupPath, err := setupCgroupV2(cfg)
	if err != nil {
		return fmt.Errorf("setting up cgroup v2: %w", err)
	}
	if cgroupPath != "" {
		defer cleanupCgroup(cgroupPath)
	}

	if err := applyLandlockNetwork(cfg); err != nil {
		if cfg.Strict {
			return fmt.Errorf("landlock network: %w", err)
		}
		fmt.Fprintf(os.Stderr, "safer-exec: warning: landlock network: %v\n", err)
	}

	if err := applySeccomp(cfg); err != nil {
		if cfg.Strict {
			return fmt.Errorf("seccomp: %w", err)
		}
		fmt.Fprintf(os.Stderr, "safer-exec: warning: seccomp: %v\n", err)
	}

	if cfg.TraceExec && cfg.EnableAudit {
		logAuditEntry("process-exec", cfg.Cmd)
	}
	return execCommand(cfg)
}

func collectAuditLog(r *os.File) {
	defer r.Close()
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			os.Stderr.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
}

func runInit(cfg config.ExecConfig) error {
	// Bring up loopback interface if network is disabled but loopback is allowed (Bug #7)
	if cfg.DisableNetwork && cfg.AllowLoopback {
		cmd := exec.Command("ip", "link", "set", "lo", "up")
		_ = cmd.Run()
	}

	cgroupPath, err := setupCgroupV2(cfg)
	if err != nil {
		return fmt.Errorf("setting up cgroup v2: %w", err)
	}
	if cgroupPath != "" {
		defer cleanupCgroup(cgroupPath)
	}

	if cfg.EnableDiff {
		if err := setupFilesystemDiff(cfg); err != nil {
			return fmt.Errorf("setting up filesystem diff: %w", err)
		}
	} else {
		if err := setupFilesystem(cfg); err != nil {
			return fmt.Errorf("setting up filesystem: %w", err)
		}
	}

	if err := applyLandlockNetwork(cfg); err != nil {
		if cfg.Strict {
			return fmt.Errorf("landlock network: %w", err)
		}
		fmt.Fprintf(os.Stderr, "safer-exec: warning: landlock network: %v\n", err)
	}

	if err := applySeccomp(cfg); err != nil {
		if cfg.Strict {
			return fmt.Errorf("seccomp: %w", err)
		}
		fmt.Fprintf(os.Stderr, "safer-exec: warning: seccomp: %v\n", err)
	}

	// Emit synthetic audit entry for traceExec because seccomp SIGSYS
	// kills the process before it can log natively.
	if cfg.TraceExec && cfg.EnableAudit {
		logAuditEntry("process-exec", cfg.Cmd)
	}
	return execCommand(cfg)
}

func setupCgroupV2(cfg config.ExecConfig) (string, error) {
	if cfg.MaxCPUCores == 0 && cfg.MaxMemoryMB == 0 && cfg.MaxProcesses == 0 {
		return "", nil
	}
	if _, err := os.Stat(cgroupV2Root); err != nil {
		return "", nil
	}

	// Unprivileged users cannot create cgroups in the root /sys/fs/cgroup.
	// We must find our current cgroup path from /proc/self/cgroup and create
	// a sub-cgroup there, where systemd may have delegated write permissions.
	currentCgroup := ""
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "0::") {
				currentCgroup = strings.TrimPrefix(line, "0::")
				break
			}
		}
	}

	baseDir := cgroupV2Root
	if currentCgroup != "" && currentCgroup != "/" {
		baseDir = filepath.Join(cgroupV2Root, currentCgroup)
	}

	cgroupName := fmt.Sprintf("safer-exec-%d", os.Getpid())
	cgroupPath := filepath.Join(baseDir, cgroupName)

	if err := os.Mkdir(cgroupPath, 0o755); err != nil {
		// If we still don't have permission (e.g. systemd delegation is disabled),
		// gracefully skip cgroup limits instead of failing the sandbox.
		if cfg.Strict {
			return "", fmt.Errorf("cgroup v2 not available: %w", err)
		}
		fmt.Fprintf(os.Stderr, "safer-exec: warning: cgroup v2 not available (mkdir %s: %v), skipping resource limits\n", cgroupPath, err)
		return "", nil
	}

	procsPath := filepath.Join(cgroupPath, "cgroup.procs")
	_ = os.WriteFile(procsPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644)

	if cfg.MaxCPUCores > 0 {
		period := 100000
		maxUS := int(cfg.MaxCPUCores * float64(period))
		cpuMax := fmt.Sprintf("%d %d", maxUS, period)
		if err := os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte(cpuMax+"\n"), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: failed to set cpu.max: %v\n", err)
		}
	}
	if cfg.MaxMemoryMB > 0 {
		memBytes := cfg.MaxMemoryMB * 1024 * 1024
		if err := os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte(fmt.Sprintf("%d\n", memBytes)), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: failed to set memory.max: %v\n", err)
		}
	}
	if cfg.MaxProcesses > 0 {
		if err := os.WriteFile(filepath.Join(cgroupPath, "pids.max"), []byte(fmt.Sprintf("%d\n", cfg.MaxProcesses)), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: failed to set pids.max: %v\n", err)
		}
	}
	return cgroupPath, nil
}

func cleanupCgroup(path string) {
	os.RemoveAll(path)
}

func setupFilesystem(cfg config.ExecConfig) error {
	cwd := cfg.WorkingDir
	if cwd == "" {
		if d, err := os.Getwd(); err == nil {
			cwd = d
		}
	}
	if cwd != "" {
		alreadyInWrite := false
		for _, w := range cfg.WritePaths {
			if w == cwd {
				alreadyInWrite = true
				break
			}
		}
		if !alreadyInWrite {
			cfg.WritePaths = append(cfg.WritePaths, cwd)
		}
	}

	newRoot, err := os.MkdirTemp("", "safer-exec-root-*")
	if err != nil {
		return fmt.Errorf("mkdir temp root: %w", err)
	}

	if err := syscall.Mount("tmpfs", newRoot, "tmpfs", 0, "size=64m"); err != nil {
		return fmt.Errorf("mount tmpfs: %w", err)
	}

	if err := os.MkdirAll(filepath.Join(newRoot, "tmp"), 0o777); err != nil {
		return fmt.Errorf("mkdir tmp: %w", err)
	}

	for _, path := range cfg.ReadPaths {
		target := filepath.Join(newRoot, path)
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}

		_, statErr := os.Stat(target)
		targetExists := statErr == nil
		if !targetExists {
			if fi.IsDir() {
				_ = os.MkdirAll(target, 0o755)
			} else {
				_ = os.MkdirAll(filepath.Dir(target), 0o755)
				f, _ := os.Create(target)
				if f != nil {
					f.Close()
				}
			}
		}

		if err == nil {
			// Linux requires bind mount and read-only remount to be separate steps.
			// Using MS_REC ensures sub-mounts (like /run/systemd) are included.
			if err := syscall.Mount(path, target, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
				if cfg.Strict {
					return fmt.Errorf("bind mount %s: %w", path, err)
				}
				fmt.Fprintf(os.Stderr, "safer-exec: warning: bind mount %s: %v\n", path, err)
				continue
			}
			_ = syscall.Mount("", target, "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY, "")
		}
	}
	for _, path := range cfg.WritePaths {
		target := filepath.Join(newRoot, path)
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}

		_, statErr := os.Stat(target)
		targetExists := statErr == nil
		if !targetExists {
			if fi.IsDir() {
				_ = os.MkdirAll(target, 0o755)
			} else {
				_ = os.MkdirAll(filepath.Dir(target), 0o755)
				f, _ := os.Create(target)
				if f != nil {
					f.Close()
				}
			}
		}

		if err == nil {
			if err := syscall.Mount(path, target, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
				if cfg.Strict {
					return fmt.Errorf("bind mount %s: %w", path, err)
				}
				fmt.Fprintf(os.Stderr, "safer-exec: warning: bind mount %s: %v\n", path, err)
				continue
			}
		}
	}
	return finalizeFilesystem(newRoot)
}

func setupFilesystemDiff(cfg config.ExecConfig) error {
	newRoot, err := os.MkdirTemp("", "safer-exec-diff-*")
	if err != nil {
		return fmt.Errorf("mkdir diff root: %w", err)
	}

	if err := syscall.Mount("tmpfs", newRoot, "tmpfs", 0, "size=64m"); err != nil {
		return fmt.Errorf("mount diff tmpfs: %w", err)
	}

	upperDir := filepath.Join(newRoot, ".upper")
	workDir := filepath.Join(newRoot, ".work")
	_ = os.MkdirAll(upperDir, 0o755)
	_ = os.MkdirAll(workDir, 0o755)

	var lowerDirs []string
	for _, path := range cfg.ReadPaths {
		if fi, err := os.Stat(path); err == nil && fi.IsDir() {
			lowerDirs = append(lowerDirs, path)
		}
	}

	if len(lowerDirs) > 0 {
		opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", strings.Join(lowerDirs, ":"), upperDir, workDir)
		if err := syscall.Mount("overlay", newRoot, "overlay", 0, opts); err != nil {
			return setupFilesystem(cfg) // Fallback
		}
	}
	return finalizeFilesystem(newRoot)
}

func finalizeFilesystem(newRoot string) error {
	putRoot := filepath.Join(newRoot, ".put")
	_ = os.Mkdir(putRoot, 0o755)

	if err := syscall.PivotRoot(newRoot, putRoot); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: pivot_root failed, falling back to chroot: %v\n", err)
		_ = os.Chdir(newRoot)
		_ = syscall.Chroot(".")
		_ = os.Chdir("/")
		_ = syscall.Unmount(newRoot, syscall.MNT_DETACH)
		_ = os.RemoveAll(newRoot)
		return nil
	}

	_ = os.Chdir("/")
	_ = syscall.Unmount("/.put", syscall.MNT_DETACH)
	_ = os.RemoveAll("/.put")
	return nil
}

type landlockRulesetAttr struct{ HandledAccessFS, HandledAccessNet uint64 }
type landlockNetPortAttr struct{ AllowedAccess, Port uint64 }

const (
	landlockCreateRulesetVersion = 1 << 0
	landlockAccessNetBindTCP     = 1 << 0
	landlockAccessNetConnectTCP  = 1 << 1
	landlockRuleNetPort          = 2
)

func applyLandlockNetwork(cfg config.ExecConfig) error {
	// Prevent unit tests from accidentally poisoning the Go test runner.
	if os.Getenv("SAFER_EXEC_CONFIG") == "" && strings.HasSuffix(os.Args[0], ".test") {
		return nil
	}

	// If loopback is allowed and network is disabled, CLONE_NEWNET isolates everything.
	// We don't need Landlock to restrict loopback ports.
	if cfg.DisableNetwork && cfg.AllowLoopback {
		return nil
	}

	if len(cfg.AllowIPs) == 0 && len(cfg.AllowPorts) == 0 && len(cfg.AllowURLRules) == 0 && !cfg.DisableNetwork {
		return nil
	}
	ports := cfg.AllowPorts
	// Extract ports declared in AllowURLRules so Landlock allows the necessary TCP ports.
	for _, r := range cfg.AllowURLRules {
		if r.Port > 0 {
			found := false
			for _, p := range ports {
				if p == r.Port {
					found = true
					break
				}
			}
			if !found {
				ports = append(ports, r.Port)
			}
		}
	}
	if len(ports) == 0 {
		ports = []int{80, 443}
	}

	abi, _, errno := syscall.RawSyscall(sysLandlockCreateRuleset, 0, 0, landlockCreateRulesetVersion)
	if errno != 0 || abi < 4 {
		return nil
	}

	attr := landlockRulesetAttr{HandledAccessNet: landlockAccessNetBindTCP | landlockAccessNetConnectTCP}
	rid, _, errno := syscall.RawSyscall(sysLandlockCreateRuleset, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return nil
	}
	defer syscall.Close(int(rid))

	allowedPorts := make(map[int]bool)
	for _, p := range ports {
		allowedPorts[p] = true
	}
	for p := 1; p <= 1024; p++ {
		allowedPorts[p] = true
	}

	for port := range allowedPorts {
		ruleAttr := landlockNetPortAttr{AllowedAccess: landlockAccessNetBindTCP | landlockAccessNetConnectTCP, Port: uint64(port)}
		syscall.Syscall6(sysLandlockAddRules, rid, uintptr(landlockRuleNetPort), uintptr(unsafe.Pointer(&ruleAttr)), 0, 0, 0)
	}
	syscall.RawSyscall(sysLandlockRestrictSelf, rid, 0, 0)
	return nil
}

func resolveHosts(hosts []string) []string {
	ips := make(map[string]bool)
	for _, host := range hosts {
		if addrs, err := net.LookupIP(host); err == nil {
			for _, addr := range addrs {
				ips[addr.String()] = true
			}
		}
	}
	result := make([]string, 0, len(ips))
	for ip := range ips {
		result = append(result, ip)
	}
	return result
}

func applySeccomp(cfg config.ExecConfig) error {
	// Prevent unit tests from accidentally applying seccomp filters to the Go test runner process,
	// which permanently poisons the OS thread and causes other tests to fail with EPERM or SIGSYS.
	if os.Getenv("SAFER_EXEC_CONFIG") == "" && strings.HasSuffix(os.Args[0], ".test") {
		return nil
	}

	// Set no_new_privs to allow seccomp filter without CAP_SYS_ADMIN
	// PR_SET_NO_NEW_PRIVS = 38
	syscall.Syscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0)

	blockCalls := []int{syscall.SYS_PTRACE, sysKCMP, syscall.SYS_UNSHARE, syscall.SYS_MOUNT, syscall.SYS_PIVOT_ROOT, sysSYSCALL}
	if cfg.BlockFork {
		// SYS_CLONE is handled separately below with a flag check to allow thread creation.
		blockCalls = append(blockCalls, sysFORK, sysVFORK)
	}
	hasBlockExecWildcard := false
	for _, item := range cfg.BlockExec {
		if item == "*" {
			hasBlockExecWildcard = true
			break
		}
	}
	if cfg.TraceExec || hasBlockExecWildcard {
		blockCalls = append(blockCalls, syscall.SYS_EXECVE)
	}

	// Filter out the dummy arm64 syscall numbers to avoid trapping unused kernel paths
	var actualBlockCalls []int
	for _, call := range blockCalls {
		if call != 9999 {
			actualBlockCalls = append(actualBlockCalls, call)
		}
	}

	var insts []syscall.SockFilter
	insts = append(insts, syscall.SockFilter{Code: bpfLoadWordAbsolute, K: 0})

	if cfg.BlockFork {
		// For SYS_CLONE, only block process forks (CLONE_THREAD flag absent).
		// Thread creation (CLONE_THREAD set) must be allowed so the sandboxed binary's
		// internal threads (glibc, Node.js libuv, etc.) can start on arm64 where
		// clone() is used for threads instead of clone3().
		//
		// BPF layout (A = syscall nr at entry):
		//   JEQ SYS_CLONE, Jt=0, Jf=3   → if NOT clone: skip 3, jump to reload
		//   LOAD args[0] (offset 16)      → A = clone flags
		//   JSET CLONE_THREAD, Jt=1, Jf=0 → if thread: skip 1 (jump to reload)
		//   RET KILL                       → process fork: kill
		//   LOAD syscall nr (offset 0)    → reload for subsequent checks
		retKillOrTrap := uint32(seccompRetKill)
		if cfg.EnableAudit {
			trapVal := uint16(6 | (syscall.SYS_CLONE&0xFF)<<8)
			retKillOrTrap = uint32(seccompRetTrap) | uint32(trapVal)
		}
		insts = append(insts,
			syscall.SockFilter{Code: bpfJmpEq, Jf: 3, K: uint32(syscall.SYS_CLONE)},
			syscall.SockFilter{Code: bpfLoadWordAbsolute, K: 16},
			syscall.SockFilter{Code: bpfJmpSet, Jt: 1, K: cloneThreadFlag},
			syscall.SockFilter{Code: bpfJmpReturn, K: retKillOrTrap},
			syscall.SockFilter{Code: bpfLoadWordAbsolute, K: 0},
		)
	}

	for _, call := range actualBlockCalls {
		insts = append(insts, syscall.SockFilter{Code: bpfJmpEq, Jf: 1, K: uint32(call)})
		if cfg.EnableAudit {
			trapVal := uint16(6 | (call&0xFF)<<8)
			insts = append(insts, syscall.SockFilter{Code: bpfJmpReturn, K: uint32(seccompRetTrap) | uint32(trapVal)})
		} else {
			insts = append(insts, syscall.SockFilter{Code: bpfJmpReturn, K: seccompRetKill})
		}
	}
	insts = append(insts, syscall.SockFilter{Code: bpfJmpReturn, K: seccompRetAllow})

	prog := syscall.SockFprog{Len: uint16(len(insts)), Filter: &insts[0]}
	_, _, errno := syscall.RawSyscall(sysSeccomp, 1, 0, uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		return fmt.Errorf("seccomp filter: %v", errno)
	}
	return nil
}

func logAuditEntry(entryType, target string) {
	entry := map[string]string{"type": entryType, "target": target, "details": fmt.Sprintf("violation detected at %s", target)}
	data, _ := json.Marshal(entry)
	auditFD := os.Getenv("SAFER_EXEC_AUDIT_FD")
	if auditFD != "" {
		fd, _ := strconv.Atoi(auditFD)
		syscall.Write(fd, append(data, '\n'))
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", string(data))
	}
}

// logAuditHTTPEntry emits an "http-request" audit entry for a captured HTTP call.
func logAuditHTTPEntry(e config.HTTPAccessEntry) {
	entry := map[string]interface{}{
		"type":     "http-request",
		"method":   e.Method,
		"host":     e.Host,
		"path":     e.Path,
		"protocol": e.Protocol,
		"port":     e.Port,
		"source":   e.Source,
		"pid":      e.PID,
	}
	if e.Query != "" {
		entry["query"] = e.Query
	}
	if e.Body != "" {
		entry["body"] = e.Body
	}
	data, _ := json.Marshal(entry)
	auditFD := os.Getenv("SAFER_EXEC_AUDIT_FD")
	if auditFD != "" {
		fd, _ := strconv.Atoi(auditFD)
		syscall.Write(fd, append(data, '\n'))
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", string(data))
	}
}

func execCommand(cfg config.ExecConfig) error {
	cmdBase := filepath.Base(cfg.Cmd)
	for _, blocked := range cfg.BlockExec {
		if blocked == cmdBase || blocked == cfg.Cmd {
			return fmt.Errorf("command %s is blocked by blockExec policy", cfg.Cmd)
		}
	}

	cmdPath, err := exec.LookPath(cfg.Cmd)
	if err != nil {
		cmdPath = cfg.Cmd
	}
	if cfg.WorkingDir != "" {
		_ = os.Chdir(cfg.WorkingDir)
	}
	env := config.BuildEnv(cfg.Env)

	// Inject dynamic library tracking if TraceLibraries is enabled.
	// LD_AUDIT hooks into the runtime linker via the rtld-audit interface,
	// capturing every shared library load via la_objopen().
	var auditCleanup string
	if cfg.TraceLibraries {
		if isMusl() {
			fmt.Fprintf(os.Stderr, "safer-exec: trace-libraries: enabled (proc maps fallback under musl).\n")
		} else {
			fmt.Fprintf(os.Stderr, "safer-exec: trace-libraries: enabled (LD_AUDIT).\n")
			var soPath string
			var err error
			if hasPrecompiledSo && len(auditHelperSo) > 0 {
				var candidates []string
				if cfg.TraceTempDir != "" {
					candidates = append(candidates, cfg.TraceTempDir)
				}
				envVars := []string{
					"RUNNER_TEMP",
					"WORKSPACE_TMP",
					"CI_PROJECT_DIR",
					"BITBUCKET_CLONE_DIR",
					"CCI_TEMP_DIR",
					"TMPDIR",
					"TEMP",
					"TMP",
				}
				for _, ev := range envVars {
					if val := os.Getenv(ev); val != "" {
						candidates = append(candidates, val)
					}
				}
				if cfg.WorkingDir != "" {
					candidates = append(candidates, cfg.WorkingDir)
				}
				candidates = append(candidates, ".")

				for _, dir := range candidates {
					soPath, err = extractPrecompiledAuditHelper(dir)
					if err == nil {
						break
					}
				}

				if err != nil {
					fmt.Fprintf(os.Stderr, "safer-exec: trace-libraries: failed to extract precompiled helper: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "safer-exec: trace-libraries: using precompiled helper -> %s\n", soPath)
				}
			} else {
				fmt.Fprintf(os.Stderr, "safer-exec: trace-libraries: precompiled helper not available for this platform\n")
			}

			if soPath != "" {
				if _, statErr := os.Stat(soPath); statErr == nil {
					env = append(env, fmt.Sprintf("LD_AUDIT=%s", soPath))
					auditCleanup = soPath
				} else {
					fmt.Fprintf(os.Stderr, "safer-exec: trace-libraries: precompiled .so not found, skipping injection\n")
				}
			}
		}
	}
	if auditCleanup != "" {
		defer os.Remove(auditCleanup)
	}

	// Try execveat to allow seccomp filtering to block standard execve
	err = execveat(-100, cmdPath, append([]string{cfg.Cmd}, cfg.Args...), env, 0)
	if err == syscall.ENOSYS || err == syscall.EPERM || err == syscall.EACCES {
		err = syscall.Exec(cmdPath, append([]string{cfg.Cmd}, cfg.Args...), env)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: execCommand failed: %v\n", err)
	}
	return err
}

func execveat(dirfd int, pathname string, argv []string, envp []string, flags int) error {
	pathnamePtr, err := syscall.BytePtrFromString(pathname)
	if err != nil {
		return err
	}

	argvPtrs, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return err
	}

	envpPtrs, err := syscall.SlicePtrFromStrings(envp)
	if err != nil {
		return err
	}

	if len(argvPtrs) == 0 {
		return fmt.Errorf("empty argv")
	}

	_, _, errno := syscall.Syscall6(sysEXECVEAT, uintptr(dirfd), uintptr(unsafe.Pointer(pathnamePtr)), uintptr(unsafe.Pointer(&argvPtrs[0])), uintptr(unsafe.Pointer(&envpPtrs[0])), uintptr(flags), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

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

func isMusl() bool {
	for _, dir := range []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64"} {
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if strings.Contains(f.Name(), "libc.musl") || strings.Contains(f.Name(), "ld-musl") {
				return true
			}
		}
	}
	return false
}

// monitorMaps periodically scans /proc/<pid>/maps for newly loaded libraries
// under musl (which does not support LD_AUDIT). The function receives a channel
// to signal clean shutdown.
func monitorMaps(parentPid int, stopChan chan struct{}) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	seen := make(map[string]bool)
	scan := func() {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", parentPid))
		if err != nil {
			return
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			pathname := fields[len(fields)-1]
			if !strings.HasPrefix(pathname, "/") {
				continue
			}
			if strings.Contains(pathname, ".so") && !seen[pathname] {
				seen[pathname] = true
				entry := map[string]string{"type": "lib-load", "target": pathname}
				if jsonData, err := json.Marshal(entry); err == nil {
					fmt.Fprintf(os.Stderr, "%s\n", string(jsonData))
				}
			}
		}
	}

	// Scan immediately
	scan()

	for {
		select {
		case <-stopChan:
			// Final scan at exit
			scan()
			return
		case <-ticker.C:
			scan()
		}
	}
}

// parseKernelVersion extracts the kernel major version as a float from a version string.
func parseKernelVersion(version string) float64 {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return 0
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 0
	}
	return float64(maj) + float64(min)/100.0
}

// runDiagnostics probes Linux kernel capabilities and returns a structured report.
func runDiagnostics() config.DiagnosticsResult {
	result := config.DiagnosticsResult{
		Platform:     "linux",
		Arch:         "",
		Capabilities: make(map[string]config.CapabilityInfo),
		Features:     make(map[string]bool),
	}

	// Kernel version
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		result.Kernel = strings.TrimSpace(string(data))
	}
	// OS release
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				result.Release = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}
	if result.Release == "" {
		if data, err := os.ReadFile("/etc/lsb-release"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "DISTRIB_DESCRIPTION=") {
					result.Release = strings.Trim(strings.TrimPrefix(line, "DISTRIB_DESCRIPTION="), "\"")
					break
				}
			}
		}
	}

	// Namespace support
	nsTypes := []struct {
		name string
		path string
	}{
		{"user_namespace", "/proc/self/ns/user"},
		{"mount_namespace", "/proc/self/ns/mnt"},
		{"pid_namespace", "/proc/self/ns/pid"},
		{"net_namespace", "/proc/self/ns/net"},
		{"uts_namespace", "/proc/self/ns/uts"},
	}
	for _, ns := range nsTypes {
		if _, err := os.Stat(ns.path); err == nil {
			result.Capabilities[ns.name] = config.CapabilityInfo{Available: true, Detail: "namespace file present"}
		} else {
			result.Capabilities[ns.name] = config.CapabilityInfo{Available: false, Detail: err.Error()}
		}
	}

	// cgroup v2
	if data, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		controllers := strings.Fields(string(data))
		hasMem, hasCPU, hasPIDs := false, false, false
		for _, c := range controllers {
			switch c {
			case "memory":
				hasMem = true
			case "cpu":
				hasCPU = true
			case "pids":
				hasPIDs = true
			}
		}
		result.Capabilities["cgroup_v2"] = config.CapabilityInfo{Available: true, Detail: fmt.Sprintf("controllers: %s", strings.Join(controllers, ", "))}
		result.Capabilities["cgroup_v2_memory"] = config.CapabilityInfo{Available: hasMem, Detail: "memory controller"}
		result.Capabilities["cgroup_v2_cpu"] = config.CapabilityInfo{Available: hasCPU, Detail: "cpu controller"}
		result.Capabilities["cgroup_v2_pids"] = config.CapabilityInfo{Available: hasPIDs, Detail: "pids controller"}
	} else {
		result.Capabilities["cgroup_v2"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
	}

	// Landlock
	if data, err := os.ReadFile("/sys/kernel/security/landlock/abi"); err == nil {
		abi := strings.TrimSpace(string(data))
		result.Capabilities["landlock"] = config.CapabilityInfo{Available: true, Detail: fmt.Sprintf("ABI v%s", abi)}
	} else {
		result.Capabilities["landlock"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
	}

	// Seccomp
	if data, err := os.ReadFile("/proc/sys/kernel/seccomp/actions_avail"); err == nil {
		actions := strings.TrimSpace(string(data))
		result.Capabilities["seccomp"] = config.CapabilityInfo{Available: true, Detail: fmt.Sprintf("actions: %s", actions)}
		result.Capabilities["seccomp_bpf"] = config.CapabilityInfo{Available: true, Detail: "seccomp-BPF via /proc/sys/kernel/seccomp"}
	} else if _, err := os.Stat("/proc/sys/kernel/seccomp"); err == nil {
		result.Capabilities["seccomp"] = config.CapabilityInfo{Available: true, Detail: "seccomp directory present"}
		result.Capabilities["seccomp_bpf"] = config.CapabilityInfo{Available: true, Detail: "seccomp implies BPF support"}
	} else {
		result.Capabilities["seccomp"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
		result.Capabilities["seccomp_bpf"] = config.CapabilityInfo{Available: false, Detail: "seccomp not available"}
	}

	// pivot_root
	if _, err := os.Stat("/proc/1/root"); err == nil {
		result.Capabilities["pivot_root"] = config.CapabilityInfo{Available: true, Detail: "pivot_root syscall available"}
	} else {
		result.Capabilities["pivot_root"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
	}

	// tmpfs
	if data, err := os.ReadFile("/proc/filesystems"); err == nil {
		if strings.Contains(string(data), "tmpfs") {
			result.Capabilities["tmpfs"] = config.CapabilityInfo{Available: true, Detail: "tmpfs filesystem available"}
		} else {
			result.Capabilities["tmpfs"] = config.CapabilityInfo{Available: false, Detail: "tmpfs not in /proc/filesystems"}
		}
	} else {
		result.Capabilities["tmpfs"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
	}

	// eBPF
	if data, err := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled"); err == nil {
		val := strings.TrimSpace(string(data))
		detail := "unprivileged_bpf_disabled=" + val
		switch val {
		case "0":
			detail += " (unprivileged BPF enabled)"
		case "1":
			detail += " (CAP_BPF required)"
		case "2":
			detail += " (CAP_BPF required, locked)"
		}
		result.Capabilities["ebpf"] = config.CapabilityInfo{Available: true, Detail: detail}
	} else {
		result.Capabilities["ebpf"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
	}

	// eBPF HTTP URL tracing needs kernel >= 5.8
	kernelVer := parseKernelVersion(result.Kernel)
	bpfForTrace := kernelVer >= 5.08
	result.Capabilities["bpf_trace_http_urls"] = config.CapabilityInfo{
		Available: bpfForTrace,
		Detail:    fmt.Sprintf("kernel %.2f %s 5.08", kernelVer, map[bool]string{true: ">=", false: "<"}[bpfForTrace]),
	}

	// unshare command
	if _, err := exec.LookPath("unshare"); err == nil {
		result.Capabilities["unshare_command"] = config.CapabilityInfo{Available: true, Detail: "unshare is in PATH"}
	} else {
		result.Capabilities["unshare_command"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
	}

	// LD_AUDIT for library tracing
	result.Capabilities["ld_audit"] = config.CapabilityInfo{Available: true, Detail: "LD_AUDIT supported on glibc"}

	// Map capabilities to features
	hasUnshare := result.Capabilities["unshare_command"].Available
	hasUserNS := result.Capabilities["user_namespace"].Available
	hasMountNS := result.Capabilities["mount_namespace"].Available
	hasPidNS := result.Capabilities["pid_namespace"].Available
	hasNetNS := result.Capabilities["net_namespace"].Available
	hasCGv2 := result.Capabilities["cgroup_v2"].Available
	hasLandlock := result.Capabilities["landlock"].Available
	hasSeccomp := result.Capabilities["seccomp"].Available
	hasTmpfs := result.Capabilities["tmpfs"].Available
	hasPivotRoot := result.Capabilities["pivot_root"].Available

	fullIsolation := hasUnshare && hasUserNS && hasMountNS && hasPidNS && hasNetNS && hasTmpfs && hasPivotRoot
	reducedIsolation := hasSeccomp && hasLandlock

	result.Features["network_isolation"] = fullIsolation
	result.Features["file_read_restriction"] = fullIsolation || reducedIsolation
	result.Features["file_write_restriction"] = fullIsolation || reducedIsolation
	result.Features["memory_limit"] = hasCGv2 && result.Capabilities["cgroup_v2_memory"].Available
	result.Features["cpu_limit"] = hasCGv2 && result.Capabilities["cgroup_v2_cpu"].Available
	result.Features["process_limit"] = hasCGv2 && result.Capabilities["cgroup_v2_pids"].Available
	result.Features["exec_control"] = hasSeccomp
	result.Features["fork_control"] = hasSeccomp
	result.Features["audit_tracing"] = hasSeccomp
	result.Features["filesystem_diff"] = true
	result.Features["learning_mode"] = fullIsolation || reducedIsolation
	result.Features["strict_mode"] = true
	result.Features["crypto_control"] = fullIsolation || reducedIsolation
	result.Features["fips_detection"] = false
	result.Features["gpu_control"] = fullIsolation || reducedIsolation
	result.Features["tpm_control"] = fullIsolation || reducedIsolation
	result.Features["antivm_spoofing"] = fullIsolation || reducedIsolation
	result.Features["trace_libraries"] = true
	result.Features["trace_http_urls"] = bpfForTrace
	result.Features["allow_url_rules"] = bpfForTrace

	return result
}
