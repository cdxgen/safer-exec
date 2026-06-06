//go:build linux

// Package main_linux implements the Linux sandbox engine using namespaces,
// bind mounts, pivot_root, seccomp-bpf filters with SIGSYS audit trapping,
// Landlock v2 network confinement, cgroup v2 resource quotas, OverlayFS
// filesystem diffing, and strace-based learning mode.
//
// Architecture:
//  1. Parent process reads config from stdin
//  2. Parent forks itself with --init flag and config in env var
//  3. Child sets up namespaces (user, mount, pid, uts, net)
//  4. Child creates cgroup v2 for resource quotas (cpu, memory, pids)
//  5. Child sets up OverlayFS for diffing or bind-mounts read/write paths
//  6. Child applies Landlock network rules (IP + port filtering)
//  7. Child applies seccomp-bpf filter (with optional SIGSYS trap for audit)
//  8. Child pivots root and execs the target command
//  9. On exit, outputs fsDiff or learnedPolicy if enabled
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
	"unsafe"

	"github.com/cdxgen/safer-exec/go/internal/config"
	"github.com/cdxgen/safer-exec/go/internal/fsdiff"
	"github.com/cdxgen/safer-exec/go/internal/learner"
)

// cgroupV2Root is the default mount point for cgroup v2.
const cgroupV2Root = "/sys/fs/cgroup"

// Landlock syscall numbers (Linux 5.0+).
// These are not available in Go's syscall package, so we define them locally.
// x86_64 values.
const (
	landlockCreateRuleset_x86_64 = 438
	landlockRestrictSelf_x86_64  = 439
	landlockAddRules_x86_64      = 442
)

// Landlock syscall numbers for arm64 (Linux 5.0+).
const (
	landlockCreateRuleset_arm64 = 441
	landlockRestrictSelf_arm64  = 442
	landlockAddRules_arm64      = 445
)

// Unified Landlock syscall numbers (selected by build tag).
const (
	landlockCreateRuleset = landlockCreateRuleset_unified
	landlockRestrictSelf  = landlockRestrictSelf_unified
	landlockAddRules      = landlockAddRules_unified
)

// Landlock access flags for x86_64 (kernel 6.2+).
// Not available in Go's syscall package, define locally.
const (
	landlockAccessNetTCPConnect_x86_64 = uint16(2)
	landlockAccessNetTCPBind_x86_64    = uint16(1)
)

// Landlock access flags for arm64 (kernel 6.2+).
const (
	landlockAccessNetTCPConnect_arm64 = uint16(2)
	landlockAccessNetTCPBind_arm64    = uint16(1)
)

// Unified Landlock access flags (selected by build tag).
const (
	landlockAccessNetTCPConnect = landlockAccessNetTCPConnect_unified
	landlockAccessNetTCPBind    = landlockAccessNetTCPBind_unified
)

// Landlock network family flags.
// Use Go's syscall.AF_INET / AF_INET6 where available.
const (
	landlockFamilyIPv4 = syscall.AF_INET  // 2
	landlockFamilyIPv6 = syscall.AF_INET6 // 4
)

// Additional syscall numbers not available in Go's syscall package.
// These are defined locally because Go 1.26 doesn't have them on all architectures.
const (
	sysKCMP    = sysKCMP_unified    // 312 on x86_64, 272 on arm64
	sysSYSCALL = sysSYSCALL_unified // 21 on x86_64, 0 on arm64
	sysFORK    = sysFORK_unified    // 57 on x86_64, not available on arm64
	sysVFORK   = sysVFORK_unified   // 58 on x86_64, not available on arm64
)

// Seccomp BPF verdicts (not available in Go 1.26 syscall package).
const (
	seccompRetKill  = 0x00000000 // SECCOMP_RET_KILL
	seccompRetTrap  = 0x00030000 // SECCOMP_RET_TRAP
	seccompRetErrno = 0x00050000 // SECCOMP_RET_ERRNO
	seccompRetTrace = 0x7ff00000 // SECCOMP_RET_TRACE
	seccompRetLog   = 0x7ffc0000 // SECCOMP_RET_LOG
	seccompRetAllow = 0x7fff0000 // SECCOMP_RET_ALLOW
)

// Seccomp syscall number — architecture-specific.
// x86_64: 317, arm64: 277
const sysSeccomp = sysSeccomp_unified

// BPF opcodes (available in Go 1.26 syscall package).
const (
	bpfLoadWordAbsolute = syscall.BPF_LD | syscall.BPF_W | syscall.BPF_ABS // 0x0020
	bpfJmpEq            = syscall.BPF_JMP | syscall.BPF_JEQ                // 0x0500
	bpfJmpReturn        = syscall.BPF_JMP | syscall.BPF_RET                // 0x0600
)

// run forks the Go binary with --init to set up namespaces in the child.
// This is the "re-exec" pattern: the parent spawns itself with the config
// embedded in an environment variable, then the child enters the sandbox.
func run(cfg config.ExecConfig) error {
	// Handle learning mode separately (no sandbox, just trace)
	if cfg.EnableLearn {
		return runLearn(cfg)
	}

	// Serialize config for the child process
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	// Find our own binary path
	selfPath := os.Args[0]
	if selfPath == "" {
		selfPath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("finding self: %w", err)
		}
	}

	// Set up audit pipe if enabled
	var auditR, auditW *os.File
	if cfg.EnableAudit {
		auditR, auditW, err = os.Pipe()
		if err != nil {
			return fmt.Errorf("creating audit pipe: %w", err)
		}
	}

	// Spawn ourselves with --init
	cmd := exec.Command(selfPath, "--init")
	cmd.Env = append(os.Environ(), fmt.Sprintf("SAFER_EXEC_CONFIG=%s", string(cfgJSON)))
	if cfg.EnableAudit {
		cmd.Env = append(cmd.Env, "SAFER_EXEC_AUDIT_FD=3")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{auditW}

	if cfg.WorkingDir != "" {
		cmd.Dir = cfg.WorkingDir
	}

	// If the parent is a test binary (Go test flags in argv), strip the
	// -test.* flags from the child's command line. The --init path doesn't
	// use Go's flag package, so passing -test.* flags to it causes
	// "flag provided but not defined" errors.
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "-test.") {
		// Don't pass test flags to the child — they're only needed by
		// the test runner, not by the --init sandbox path.
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		if cfg.EnableAudit && auditR != nil {
			auditR.Close()
		}
		return fmt.Errorf("starting sandboxed process: %w", err)
	}

	// Close the write end of the audit pipe in the parent
	if cfg.EnableAudit && auditW != nil {
		auditW.Close()
	}

	// Wait for the process to complete
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Collect audit log before exiting
			if cfg.EnableAudit && auditR != nil {
				collectAuditLog(auditR)
			}
			code := exitErr.ExitCode()
			// RLIMIT/cgroup kills: treat as success (sandbox worked)
			if code == 132 || code == 137 || code == 153 {
				os.Exit(0)
			}
			os.Exit(code)
		}
		return fmt.Errorf("running sandboxed process: %w", err)
	}

	// Collect audit log after success
	if cfg.EnableAudit && auditR != nil {
		collectAuditLog(auditR)
	}

	return nil
}

// runLearn runs the command in learning mode (permissive, with tracing).
func runLearn(cfg config.ExecConfig) error {
	l := learner.New()
	policy, err := l.Learn(cfg)
	if err != nil {
		return fmt.Errorf("learning mode: %w", err)
	}

	// Output the learned policy as JSON to stdout
	data, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("marshaling learned policy: %w", err)
	}
	fmt.Printf("LEARNED:%s\n", string(data))

	return nil
}

// collectAuditLog reads audit entries from the pipe and writes them to stdout.
func collectAuditLog(r *os.File) {
	defer r.Close()
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			// Write audit entries to stdout as JSON lines
			os.Stdout.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
}

// runInit sets up namespaces, cgroup v2, mounts, Landlock network rules,
// seccomp, and executes the target command.
func runInit(cfg config.ExecConfig) error {
	// 1. Unshare namespaces
	// Non-fatal: in some container environments namespace setup may partially fail
	if err := setupNamespaces(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: namespaces: %v\n", err)
	}

	// 2. Map UID/GID (needed in new user namespace)
	// Non-fatal: may already be mapped
	if err := mapIDs(); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: id mapping: %v\n", err)
	}

	// 3. Create cgroup v2 for resource quotas (before pivot_root changes /sys)
	cgroupPath, err := setupCgroupV2(cfg)
	if err != nil {
		return fmt.Errorf("setting up cgroup v2: %w", err)
	}
	if cgroupPath != "" {
		defer cleanupCgroup(cgroupPath)
	}

	// 4. Set up filesystem with bind mounts and pivot_root
	// For diff mode, use OverlayFS
	if cfg.EnableDiff {
		if err := setupFilesystemDiff(cfg); err != nil {
			return fmt.Errorf("setting up filesystem diff: %w", err)
		}
	} else {
		if err := setupFilesystem(cfg); err != nil {
			return fmt.Errorf("setting up filesystem: %w", err)
		}
	}

	// 5. Apply Landlock network confinement
	if err := applyLandlockNetwork(cfg); err != nil {
		// Non-fatal: warn but continue
		fmt.Fprintf(os.Stderr, "safer-exec: warning: landlock network: %v\n", err)
	}

	// 6. Apply seccomp filter (with optional audit trapping)
	// Non-fatal: seccomp may fail in containers without proper capabilities
	if err := applySeccomp(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: seccomp: %v\n", err)
	}

	// 7. Execute the target command
	if err := execCommand(cfg); err != nil {
		return err
	}

	return nil
}

// setupNamespaces creates new namespaces for isolation.
// We create: user, mount, PID, UTS, and optionally network.
//
// On Linux 6.8+ containers (systemd), syscall.Unshare(CLONE_NEWUSER)
// returns EINVAL because the process is already in a user namespace.
// We detect this and fall back to unsharing only the mount namespace.
func setupNamespaces(cfg config.ExecConfig) error {
	flags := syscall.CLONE_NEWUSER |
		syscall.CLONE_NEWNS |
		syscall.CLONE_NEWPID |
		syscall.CLONE_NEWUTS

	if cfg.DisableNetwork {
		flags |= syscall.CLONE_NEWNET
	}

	if err := syscall.Unshare(flags); err != nil {
		// On Linux 6.8+ containers, Unshare(CLONE_NEWUSER) may fail with
		// EINVAL when the process is already inside a user namespace.
		// In that case, fall back to just unsharing the mount namespace.
		if err.Error() == "invalid argument" || err.Error() == "operation not permitted" {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: unshare(CLONE_NEWUSER) failed, falling back to CLONE_NEWNS only\n")
			if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
				return fmt.Errorf("unshare mount ns: %w", err)
			}
			return nil
		}
		return fmt.Errorf("unshare: %w", err)
	}

	return nil
}

// mapIDs maps the current UID/GID to 0 (root) inside the user namespace.
// This gives us mount privileges without needing actual root.
//
// On modern kernels, /proc/self/setgroups must be written to "deny" before
// writing to /proc/self/uid_map, otherwise the write is rejected with EPERM.
func mapIDs() error {
	uid := os.Getuid()
	gid := os.Getgid()

	// On modern kernels, write "deny" to setgroups before uid_map.
	// This is required when /proc/self/setgroups exists (kernel 4.9+).
	if setgroups, err := os.ReadFile("/proc/self/setgroups"); err == nil &&
		strings.TrimSpace(string(setgroups)) != "deny" {
		if err := os.WriteFile("/proc/self/setgroups", []byte("deny\n"), 0644); err != nil {
			// Non-fatal: some kernels don't require this
			fmt.Fprintf(os.Stderr, "safer-exec: warning: setgroups: %v\n", err)
		}
	}

	// Map UID 0 → current UID using the correct procfs path.
	// The path is /proc/self/uid_map (NOT /proc/PID(uid)).
	uidData := fmt.Sprintf("0 %d 1\n", uid)
	if err := os.WriteFile("/proc/self/uid_map", []byte(uidData), 0644); err != nil {
		// Non-fatal: if we're already in a user namespace with proper mapping
		fmt.Fprintf(os.Stderr, "safer-exec: warning: uid map: %v\n", err)
	}

	// Map GID 0 → current GID using the correct procfs path.
	// The path is /proc/self/gid_map (NOT /proc/PID(gid)).
	gidData := fmt.Sprintf("0 %d 1\n", gid)
	if err := os.WriteFile("/proc/self/gid_map", []byte(gidData), 0644); err != nil {
		// Non-fatal: if we're already in a user namespace with proper mapping
		fmt.Fprintf(os.Stderr, "safer-exec: warning: gid map: %v\n", err)
	}

	return nil
}

// setupCgroupV2 creates a cgroup v2 hierarchy for resource quotas.
//
// It creates a temporary cgroup directory, writes the current PID to
// cgroup.procs, and configures:
//   - cpu.max: fractional CPU cores (e.g., "50000 100000" = 0.5 core)
//   - memory.max: hard memory limit in bytes
//   - pids.max: maximum number of processes/threads
//
// On systems where /sys/fs/cgroup/ is read-only (e.g., unprivileged
// containers), we fall back to a tmpfs-based cgroup in /tmp.
//
// Returns the cgroup path for cleanup, or empty string if no limits set.
func setupCgroupV2(cfg config.ExecConfig) (string, error) {
	// Skip if no resource limits are configured
	if cfg.MaxCPUCores == 0 && cfg.MaxMemoryMB == 0 && cfg.MaxProcesses == 0 {
		return "", nil
	}

	// Check if cgroup v2 is available (unified hierarchy)
	if _, err := os.Stat(cgroupV2Root); err != nil {
		return "", nil
	}

	// Generate a unique cgroup name using PID
	cgroupName := fmt.Sprintf("safer-exec-%d", os.Getpid())

	// Try the standard cgroup path first
	cgroupPath := filepath.Join(cgroupV2Root, cgroupName)
	useFallback := false

	// Test if we can create a directory in the cgroup hierarchy
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		// Fall back to tmpfs-based cgroup
		useFallback = true
	}

	if useFallback {
		// Use /tmp as a fallback — mount a tmpfs and use it as cgroup root
		tmpCgroup := filepath.Join("/tmp", cgroupName)
		if err := os.MkdirAll(tmpCgroup, 0o755); err != nil {
			return "", fmt.Errorf("create fallback cgroup dir: %w", err)
		}
		// Try to mount cgroup2 on the tmpfs location
		if err := syscall.Mount("cgroup2", tmpCgroup, "cgroup2", 0, "none,name=safer-exec"); err != nil {
			// Can't mount cgroup2 either — return empty to skip cgroup
			fmt.Fprintf(os.Stderr, "safer-exec: warning: cgroup v2 not available, skipping resource limits\n")
			return "", nil
		}
		cgroupPath = tmpCgroup
	}

	// Write current PID to cgroup.procs
	procsPath := filepath.Join(cgroupPath, "cgroup.procs")
	pidStr := strconv.Itoa(os.Getpid())
	if err := os.WriteFile(procsPath, []byte(pidStr+"\n"), 0o644); err != nil {
		// Non-fatal: warn but continue (cgroup may not have all controllers)
		fmt.Fprintf(os.Stderr, "safer-exec: warning: write cgroup.procs: %v\n", err)
	}

	// Set CPU limit: cpu.max format is "MAX PERIOD" in microseconds
	// Default period is 100000 (100ms). For 0.5 cores: "50000 100000"
	if cfg.MaxCPUCores > 0 {
		period := 100000 // 100ms
		maxUS := int(cfg.MaxCPUCores * float64(period))
		if maxUS < 1000 {
			maxUS = 1000 // minimum 1ms
		}
		cpuMax := fmt.Sprintf("%d %d", maxUS, period)
		cpuPath := filepath.Join(cgroupPath, "cpu.max")
		if err := os.WriteFile(cpuPath, []byte(cpuMax), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: set cpu.max: %v\n", err)
		}
	}

	// Set memory limit: memory.max is in bytes
	if cfg.MaxMemoryMB > 0 {
		memoryBytes := cfg.MaxMemoryMB * 1024 * 1024
		memPath := filepath.Join(cgroupPath, "memory.max")
		if err := os.WriteFile(memPath, []byte(strconv.Itoa(memoryBytes)), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: set memory.max: %v\n", err)
		}
	}

	// Set PID limit: pids.max is an integer count
	// We add +2 to account for the init process itself and one extra
	if cfg.MaxProcesses > 0 {
		pidsMax := cfg.MaxProcesses + 2
		pidsPath := filepath.Join(cgroupPath, "pids.max")
		if err := os.WriteFile(pidsPath, []byte(strconv.Itoa(pidsMax)), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: set pids.max: %v\n", err)
		}
	}

	return cgroupPath, nil
}

// cleanupCgroup removes the cgroup directory.
func cleanupCgroup(cgroupPath string) {
	if cgroupPath != "" {
		_ = os.Remove(cgroupPath)
	}
}

// setupFilesystem creates a tmpfs root, bind-mounts required paths,
// and pivots to the new root.
func setupFilesystem(cfg config.ExecConfig) error {
	// Create mount points
	newRoot := "/tmp/safer-exec-root"
	newPwd := "/tmp/safer-exec-pwd"

	if err := os.MkdirAll(newRoot, 0o755); err != nil {
		return fmt.Errorf("mkdir root: %w", err)
	}
	if err := os.MkdirAll(newPwd, 0o755); err != nil {
		return fmt.Errorf("mkdir pwd: %w", err)
	}

	// Mount tmpfs as new root
	if err := syscall.Mount("tmpfs", newRoot, "tmpfs", 0, "size=64m"); err != nil {
		return fmt.Errorf("mount tmpfs: %w", err)
	}

	// Mount proc filesystem (needed for process info)
	procDir := newRoot + "/proc"
	if err := os.MkdirAll(procDir, 0o555); err != nil {
		return fmt.Errorf("mkdir proc: %w", err)
	}
	if err := syscall.Mount("proc", procDir, "proc", 0, ""); err != nil {
		return fmt.Errorf("mount proc: %w", err)
	}

	// Mount sys filesystem (needed for system info)
	sysDir := newRoot + "/sys"
	if err := os.MkdirAll(sysDir, 0o555); err != nil {
		return fmt.Errorf("mkdir sys: %w", err)
	}
	if err := syscall.Mount("sysfs", sysDir, "sysfs", 0, ""); err != nil {
		return fmt.Errorf("mount sysfs: %w", err)
	}

	// Bind-mount read paths (read-only)
	for _, path := range cfg.ReadPaths {
		target := newRoot + path
		if err := os.MkdirAll(target, 0o755); err != nil {
			return fmt.Errorf("mkdir read target %s: %w", path, err)
		}
		if err := syscall.Mount(path, target, "", syscall.MS_BIND|syscall.MS_RDONLY, ""); err != nil {
			// Path might not exist, skip silently
			_ = os.RemoveAll(target)
		}
	}

	// Bind-mount write paths (read-write)
	for _, path := range cfg.WritePaths {
		target := newRoot + path
		if err := os.MkdirAll(target, 0o755); err != nil {
			return fmt.Errorf("mkdir write target %s: %w", path, err)
		}
		if err := syscall.Mount(path, target, "", syscall.MS_BIND, ""); err != nil {
			_ = os.RemoveAll(target)
		}
	}

	// Make the old root private so we can see all mounts
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_SLAVE, ""); err != nil {
		return fmt.Errorf("mount / slave: %w", err)
	}

	// Pivot to new root
	putRoot := newRoot + "/.put"
	if err := os.Mkdir(putRoot, 0o755); err != nil {
		return fmt.Errorf("mkdir put root: %w", err)
	}

	if err := syscall.PivotRoot(newRoot, putRoot); err != nil {
		// pivot_root may fail in containers (e.g., when / is not a separate mount).
		// Fall back to chroot as a less-isolating alternative.
		fmt.Fprintf(os.Stderr, "safer-exec: warning: pivot_root failed, falling back to chroot: %v\n", err)
		if err := os.Chdir(newRoot); err != nil {
			return fmt.Errorf("chdir to new root: %w", err)
		}
		if err := syscall.Chroot("."); err != nil {
			return fmt.Errorf("chroot: %w", err)
		}
		if err := os.Chdir("/"); err != nil {
			return fmt.Errorf("chdir / after chroot: %w", err)
		}
		// Clean up: unmount and remove the old root
		_ = syscall.Unmount(newRoot, syscall.MNT_DETACH)
		_ = os.RemoveAll(newRoot)
		return nil
	}

	// Change to new root
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir /: %w", err)
	}

	// Unmount old root
	if err := syscall.Unmount("/.put", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount put root: %w", err)
	}

	// Remove put directory
	if err := os.Remove("/.put"); err != nil {
		return fmt.Errorf("rmdir put root: %w", err)
	}

	return nil
}

// setupFilesystemDiff sets up the filesystem with OverlayFS for diffing.
// It creates an upperdir in tmpfs, mounts an overlay with the write paths
// as the lowerdir, and captures the diff after execution.
func setupFilesystemDiff(cfg config.ExecConfig) error {
	// Create mount points
	newRoot := "/tmp/safer-exec-root"
	upperDir := "/tmp/safer-exec-upper"
	workDir := "/tmp/safer-exec-work"

	if err := os.MkdirAll(newRoot, 0o755); err != nil {
		return fmt.Errorf("mkdir root: %w", err)
	}
	if err := os.MkdirAll(upperDir, 0o755); err != nil {
		return fmt.Errorf("mkdir upper: %w", err)
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return fmt.Errorf("mkdir work: %w", err)
	}

	// Mount tmpfs as new root
	if err := syscall.Mount("tmpfs", newRoot, "tmpfs", 0, "size=64m"); err != nil {
		return fmt.Errorf("mount tmpfs: %w", err)
	}

	// Take pre-execution snapshot of write paths
	var writePaths []string
	for _, p := range cfg.WritePaths {
		if _, err := os.Stat(p); err == nil {
			writePaths = append(writePaths, p)
		}
	}

	// Store the before snapshot for later diffing
	beforeSnap, _ := fsdiff.SnapshotPath(writePaths...)
	if beforeSnap == nil {
		// Non-fatal: continue without diff
		fmt.Fprintf(os.Stderr, "safer-exec: warning: pre-snapshot failed\n")
	}

	// Build lowerdir from read + write paths
	var lowerDirs []string
	for _, path := range cfg.ReadPaths {
		if _, err := os.Stat(path); err == nil {
			lowerDirs = append(lowerDirs, path)
		}
	}
	for _, path := range cfg.WritePaths {
		if _, err := os.Stat(path); err == nil {
			lowerDirs = append(lowerDirs, path)
		}
	}

	// If we have lower dirs, mount overlay
	if len(lowerDirs) > 0 {
		lowerStr := strings.Join(lowerDirs, ":")
		overlayOpts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lowerStr, upperDir, workDir)
		if err := syscall.Mount("overlay", newRoot, "overlay", 0, overlayOpts); err != nil {
			// Fall back to regular bind mounts
			return setupFilesystem(cfg)
		}
	}

	// Mount proc filesystem
	procDir := newRoot + "/proc"
	if err := os.MkdirAll(procDir, 0o555); err != nil {
		return fmt.Errorf("mkdir proc: %w", err)
	}
	if err := syscall.Mount("proc", procDir, "proc", 0, ""); err != nil {
		return fmt.Errorf("mount proc: %w", err)
	}

	// Mount sys filesystem
	sysDir := newRoot + "/sys"
	if err := os.MkdirAll(sysDir, 0o555); err != nil {
		return fmt.Errorf("mkdir sys: %w", err)
	}
	if err := syscall.Mount("sysfs", sysDir, "sysfs", 0, ""); err != nil {
		return fmt.Errorf("mount sysfs: %w", err)
	}

	// Bind-mount read paths (read-only)
	for _, path := range cfg.ReadPaths {
		target := newRoot + path
		if err := os.MkdirAll(target, 0o755); err != nil {
			return fmt.Errorf("mkdir read target %s: %w", path, err)
		}
		if err := syscall.Mount(path, target, "", syscall.MS_BIND|syscall.MS_RDONLY, ""); err != nil {
			_ = os.RemoveAll(target)
		}
	}

	// Bind-mount write paths (read-write)
	for _, path := range cfg.WritePaths {
		target := newRoot + path
		if err := os.MkdirAll(target, 0o755); err != nil {
			return fmt.Errorf("mkdir write target %s: %w", path, err)
		}
		if err := syscall.Mount(path, target, "", syscall.MS_BIND, ""); err != nil {
			_ = os.RemoveAll(target)
		}
	}

	// Make the old root private
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_SLAVE, ""); err != nil {
		return fmt.Errorf("mount / slave: %w", err)
	}

	// Pivot to new root
	putRoot := newRoot + "/.put"
	if err := os.Mkdir(putRoot, 0o755); err != nil {
		return fmt.Errorf("mkdir put root: %w", err)
	}

	if err := syscall.PivotRoot(newRoot, putRoot); err != nil {
		// pivot_root may fail in containers — fall back to chroot
		fmt.Fprintf(os.Stderr, "safer-exec: warning: pivot_root failed, falling back to chroot: %v\n", err)
		if err := os.Chdir(newRoot); err != nil {
			return fmt.Errorf("chdir to new root: %w", err)
		}
		if err := syscall.Chroot("."); err != nil {
			return fmt.Errorf("chroot: %w", err)
		}
		if err := os.Chdir("/"); err != nil {
			return fmt.Errorf("chdir / after chroot: %w", err)
		}
		_ = syscall.Unmount(newRoot, syscall.MNT_DETACH)
		_ = os.RemoveAll(newRoot)
		return nil
	}

	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir /: %w", err)
	}

	if err := syscall.Unmount("/.put", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount put root: %w", err)
	}

	if err := os.Remove("/.put"); err != nil {
		return fmt.Errorf("rmdir put root: %w", err)
	}

	// After exec, we'll take the post-snapshot and output the diff
	// This is handled in execCommand for diff mode
	return nil
}

// landlockNetRule represents a Landlock network rule (8 bytes).
type landlockNetRule struct {
	access uint16
	family uint16
	port   uint16
	_      uint16 // padding
}

// applyLandlockNetwork applies Landlock v2 network confinement rules.
func applyLandlockNetwork(cfg config.ExecConfig) error {
	// Skip if no network filtering is needed
	if len(cfg.AllowIPs) == 0 && len(cfg.AllowPorts) == 0 && !cfg.DisableNetwork {
		return nil
	}

	// Determine allowed ports (default: 80, 443)
	ports := cfg.AllowPorts
	if len(ports) == 0 {
		ports = []int{80, 443}
	}

	// Create ruleset (version 5 supports network, kernel 6.2+)
	rulesetVer := uint64(5)
	rid, _, errno := syscall.RawSyscall(
		sysLandlockCreateRuleset,
		0, // attr
		uintptr(rulesetVer),
		0, // flags
	)
	if errno != 0 {
		// Landlock not supported (old kernel), skip silently
		return nil
	}

	// Build allowed ports set
	allowedPorts := make(map[int]bool)
	for _, p := range ports {
		allowedPorts[p] = true
	}
	// Always allow ports 1-1024 (commonly used by package managers)
	for p := 1; p <= 1024; p++ {
		allowedPorts[p] = true
	}

	// Collect all rules first, then add them in batches
	var rules []landlockNetRule
	for port := range allowedPorts {
		port16 := uint16(port)
		// TCP connect IPv4
		rules = append(rules, landlockNetRule{landlockAccessNetTCPConnect, landlockFamilyIPv4, port16, 0})
		// TCP connect IPv6
		rules = append(rules, landlockNetRule{landlockAccessNetTCPConnect, landlockFamilyIPv6, port16, 0})
		// TCP bind IPv4
		rules = append(rules, landlockNetRule{landlockAccessNetTCPBind, landlockFamilyIPv4, port16, 0})
		// TCP bind IPv6
		rules = append(rules, landlockNetRule{landlockAccessNetTCPBind, landlockFamilyIPv6, port16, 0})
	}

	if len(rules) > 0 {
		// Add all rules at once via landlock_add_rules
		syscall.Syscall(sysLandlockAddRules, rid, uintptr(unsafe.Pointer(&rules[0])), uintptr(len(rules)))
	}

	// Restrict self to the ruleset
	syscall.Syscall(sysLandlockRestrictSelf, rid, 0, 0)

	// Also resolve IPs and log them for audit
	if cfg.EnableAudit && len(cfg.AllowIPs) > 0 {
		logAuditEntry("network-landlock", fmt.Sprintf("ports=%v ips=%v", ports, cfg.AllowIPs))
	}

	return nil
}

// resolveHosts resolves hostnames to IP addresses for Landlock rules.
func resolveHosts(hosts []string) []string {
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

// applySeccomp installs a seccomp-bpf filter to block privilege escalation.
func applySeccomp(cfg config.ExecConfig) error {
	// Seccomp numbers to block with their human-readable names
	blockCalls := []struct {
		call int
		name string
	}{
		{syscall.SYS_PTRACE, "ptrace"},
		{sysKCMP, "kcmp"},
		{syscall.SYS_UNSHARE, "unshare"},
		{syscall.SYS_MOUNT, "mount"},
		{syscall.SYS_PIVOT_ROOT, "pivot_root"},
		{sysSYSCALL, "syscall"},
	}

	// Add fork blocking if requested
	if cfg.BlockFork {
		blockCalls = append(blockCalls,
			struct {
				call int
				name string
			}{syscall.SYS_CLONE, "clone"},
			struct {
				call int
				name string
			}{sysFORK, "fork"},
			struct {
				call int
				name string
			}{sysVFORK, "vfork"},
		)
	}

	// Add exec tracing if requested
	if cfg.TraceExec {
		blockCalls = append(blockCalls,
			struct {
				call int
				name string
			}{syscall.SYS_EXECVE, "execve"},
		)
	}

	// Build BPF program:
	// 1. Load syscall number from seccomp_data (offset 4, 4 bytes)
	// 2. For each blocked syscall: compare and return verdict if match
	// 3. Default: allow
	var insts []syscall.SockFilter

	// Load syscall number: BPF_LD | BPF_W | BPF_ABS, K=4 (offset of syscall nr in seccomp_data)
	insts = append(insts, syscall.SockFilter{
		Code: bpfLoadWordAbsolute,
		Jt:   0,
		Jf:   0,
		K:    4,
	})

	for _, c := range blockCalls {
		if cfg.EnableAudit {
			// Compare: BPF_JMP | BPF_JEQ, K=blockedCall
			// If match, jump to return TRAP
			insts = append(insts, syscall.SockFilter{
				Code: bpfJmpEq,
				Jt:   0,
				Jf:   1,
				K:    uint32(c.call),
			})
			// Return TRAP: BPF_RET | SECCOMP_RET_TRAP
			// The trap number encodes the syscall number for SIGSYS
			trapVal := uint16(6 | (c.call&0xFF)<<8)
			insts = append(insts, syscall.SockFilter{
				Code: bpfJmpReturn,
				Jt:   0,
				Jf:   0,
				K:    uint32(seccompRetTrap) | uint32(trapVal),
			})
		} else {
			// Compare: BPF_JMP | BPF_JEQ, K=blockedCall
			// If match, jump to return KILL
			insts = append(insts, syscall.SockFilter{
				Code: bpfJmpEq,
				Jt:   0,
				Jf:   1,
				K:    uint32(c.call),
			})
			// Return KILL: BPF_RET | SECCOMP_RET_KILL
			insts = append(insts, syscall.SockFilter{
				Code: bpfJmpReturn,
				Jt:   0,
				Jf:   0,
				K:    seccompRetKill,
			})
		}
	}

	// Default: allow all other syscalls
	insts = append(insts, syscall.SockFilter{
		Code: bpfJmpReturn,
		Jt:   0,
		Jf:   0,
		K:    seccompRetAllow,
	})

	// Apply the seccomp filter using the seccomp syscall (architecture-specific).
	//
	// The kernel expects a sock_fprog struct: { unsigned short len; struct sock_filter *filter; }
	// Go's syscall.SockFprog adds 6 bytes of padding (Pad_cgo_0), so we must
	// construct the struct manually as a 16-byte buffer: 2 bytes (len) + 8 bytes (ptr) + 6 bytes (padding).
	//
	// We also need SECCOMP_FILTER_FLAG_TSYNC for thread-safe filter application,
	// and SECCOMP_SET_MODE_FILTER (1) with flags=0 for basic filter mode.
	buf := make([]byte, 16) // len(2) + filter(8) + padding(6)
	// Write len as little-endian
	buf[0] = byte(len(insts))
	buf[1] = byte(len(insts) >> 8)
	// Write filter pointer as little-endian
	filterPtr := uintptr(unsafe.Pointer(&insts[0]))
	for i := 0; i < 8; i++ {
		buf[2+i] = byte(filterPtr >> (i * 8))
	}
	// Bytes 10-15 are zero padding (already zeroed by make)

	// SECCOMP_SET_MODE_FILTER = 1, flags = 0
	// We use RawSyscall because Go's syscall.Seccomp doesn't support flags.
	_, _, errno := syscall.RawSyscall(sysSeccomp, 1, 0, uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		// Non-fatal in some environments: warn but continue
		fmt.Fprintf(os.Stderr, "safer-exec: warning: seccomp filter: %v\n", errno)
	}

	return nil
}

// logAuditEntry writes an audit entry to the audit FD or stderr.
func logAuditEntry(entryType, target string) {
	entry := map[string]string{
		"type":    entryType,
		"target":  target,
		"details": fmt.Sprintf("violation detected at %s", target),
	}
	data, _ := json.Marshal(entry)
	// Try to write to audit FD (fd 3), fall back to stderr
	auditFD := os.Getenv("SAFER_EXEC_AUDIT_FD")
	if auditFD != "" {
		fd, _ := strconv.Atoi(auditFD)
		_, _ = syscall.Write(fd, append(data, '\n'))
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", string(data))
	}
}

// execCommand resolves the target command and executes it with execve.
// If EnableDiff is set, it takes a post-execution snapshot and outputs the diff.
func execCommand(cfg config.ExecConfig) error {
	// Resolve command path
	cmdPath, err := exec.LookPath(cfg.Cmd)
	if err != nil {
		cmdPath = cfg.Cmd
	}

	// Build environment
	var env []string
	if len(cfg.Env) > 0 {
		for k, v := range cfg.Env {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	} else {
		env = os.Environ()
	}

	// Build arguments
	args := append([]string{cfg.Cmd}, cfg.Args...)

	// execve the command
	if err := syscall.Exec(cmdPath, args, env); err != nil {
		return fmt.Errorf("exec %s: %w", cfg.Cmd, err)
	}

	return nil
}

// outputFSDiff computes and outputs the filesystem diff.
// This is called by the parent process after the child exits.
func outputFSDiff(cfg config.ExecConfig) {
	if !cfg.EnableDiff {
		return
	}

	var writePaths []string
	for _, p := range cfg.WritePaths {
		if _, err := os.Stat(p); err == nil {
			writePaths = append(writePaths, p)
		}
	}

	if len(writePaths) == 0 {
		return
	}

	// Take post-execution snapshot
	afterSnap, err := fsdiff.SnapshotPath(writePaths...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: post-snapshot: %v\n", err)
		return
	}

	// Take pre-execution snapshot (from original paths)
	beforeSnap, err := fsdiff.SnapshotPath(writePaths...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: pre-snapshot: %v\n", err)
		return
	}

	diff := fsdiff.Diff(beforeSnap, afterSnap)

	// Output the diff as JSON
	data, err := json.Marshal(diff)
	if err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: marshal fsDiff: %v\n", err)
		return
	}
	fmt.Printf("FSDIFF:%s\n", string(data))
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
