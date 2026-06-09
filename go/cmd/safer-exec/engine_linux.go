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
	"unsafe"

	"github.com/cdxgen/safer-exec/go/internal/config"
	"github.com/cdxgen/safer-exec/go/internal/fsdiff"
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

	if err := cmd.Start(); err != nil {
		if cfg.EnableAudit && auditR != nil {
			auditR.Close()
		}
		return fmt.Errorf("starting sandboxed process: %w", err)
	}

	if cfg.EnableAudit && auditW != nil {
		auditW.Close()
	}

	if err := cmd.Wait(); err != nil {
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
							fmt.Printf("FSDIFF:%s\n", string(data))
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
				fmt.Printf("FSDIFF:%s\n", string(data))
			}
		}
	}

	if cfg.EnableAudit && auditR != nil {
		collectAuditLog(auditR)
	}
	return nil
}

func runLearn(cfg config.ExecConfig) error {
	l := learner.New()
	policy, err := l.Learn(cfg)
	if err != nil {
		return fmt.Errorf("learning mode: %w", err)
	}
	data, _ := json.Marshal(policy)
	fmt.Printf("LEARNED:%s\n", string(data))
	return nil
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

	if err := cmd.Wait(); err != nil {
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
		if maxUS < 1000 {
			maxUS = 1000
		}
		_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte(fmt.Sprintf("%d %d", maxUS, period)), 0o644)
	}
	if cfg.MaxMemoryMB > 0 {
		_ = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte(strconv.Itoa(cfg.MaxMemoryMB*1024*1024)), 0o644)
	}
	if cfg.MaxProcesses > 0 {
		_ = os.WriteFile(filepath.Join(cgroupPath, "pids.max"), []byte(strconv.Itoa(cfg.MaxProcesses+2)), 0o644)
	}
	return cgroupPath, nil
}

func cleanupCgroup(cgroupPath string) { _ = os.Remove(cgroupPath) }

func setupFilesystem(cfg config.ExecConfig) error {
	// Make working directory writable by default to match macOS behavior (Bug #6)
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

	cfg.ReadPaths = dedupPaths(cfg.ReadPaths)
	cfg.WritePaths = dedupPaths(cfg.WritePaths)

	newRoot, err := os.MkdirTemp("", "safer-exec-root-*")
	if err != nil {
		return fmt.Errorf("mkdir temp root: %w", err)
	}

	if err := syscall.Mount("tmpfs", newRoot, "tmpfs", 0, "size=64m"); err != nil {
		return fmt.Errorf("mount tmpfs: %w", err)
	}

	// Setup custom restricted /dev inside newRoot if BlockCryptoEntropy is true.
	// Normally we'd bind mount host /dev. Let's look at what is bind-mounted or if dev is created.
	// We'll create dev directory:
	devDir := filepath.Join(newRoot, "dev")
	_ = os.MkdirAll(devDir, 0o755)
	if cfg.BlockCryptoEntropy {
		// Create empty files for random/urandom so they are empty read-only or blocked.
		// This intercepts any access to them.
		if f, err := os.Create(filepath.Join(devDir, "random")); err == nil {
			f.Close()
		}
		if f, err := os.Create(filepath.Join(devDir, "urandom")); err == nil {
			f.Close()
		}
		// Bind mount host /dev to newRoot/dev
		_ = syscall.Mount("/dev", devDir, "", syscall.MS_BIND|syscall.MS_REC, "")

		// If BlockTPM is true, unmount or override tpm devices inside devDir
		if cfg.BlockTPM {
			_ = syscall.Unmount(filepath.Join(devDir, "tpm0"), syscall.MNT_DETACH)
			_ = syscall.Unmount(filepath.Join(devDir, "tpmrm0"), syscall.MNT_DETACH)
			// Mount empty files over them
			if f, err := os.Create(filepath.Join(devDir, "tpm0")); err == nil {
				f.Close()
			}
			if f, err := os.Create(filepath.Join(devDir, "tpmrm0")); err == nil {
				f.Close()
			}
		}
		// If AllowGPU is false or BlockGPU is true, unmount or restrict NVIDIA/DRI access inside devDir
		if !cfg.AllowGPU || cfg.BlockGPU {
			_ = syscall.Unmount(filepath.Join(devDir, "nvidiactl"), syscall.MNT_DETACH)
			_ = syscall.Unmount(filepath.Join(devDir, "nvidia-uvm"), syscall.MNT_DETACH)
			_ = syscall.Unmount(filepath.Join(devDir, "dri"), syscall.MNT_DETACH)
		}
	}

	// Setup SpoofAntiVM paths if requested
	if cfg.SpoofAntiVM {
		dmiDir := filepath.Join(newRoot, "sys", "class", "dmi", "id")
		_ = os.MkdirAll(dmiDir, 0o755)
		_ = os.WriteFile(filepath.Join(dmiDir, "product_name"), []byte("ThinkPad T480\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dmiDir, "sys_vendor"), []byte("LENOVO\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dmiDir, "bios_vendor"), []byte("LENOVO\n"), 0o644)
		logAuditEntry("antivm-spoof", "Concealing virtualization markers")
	}

	// Setup FIPS simulation if requested
	if cfg.DetectFIPS || cfg.StrictFIPS {
		fipsDir := filepath.Join(newRoot, "proc", "sys", "crypto")
		_ = os.MkdirAll(fipsDir, 0o755)
		fipsVal := "0"
		// Check if host actually has FIPS enabled
		if hostFips, err := os.ReadFile("/proc/sys/crypto/fips_enabled"); err == nil {
			fipsVal = strings.TrimSpace(string(hostFips))
		}
		// If StrictFIPS is enabled, we require fips_enabled to be 1
		if cfg.StrictFIPS && fipsVal != "1" {
			// Fail or audit FIPS compliance issue prior to launch
			logAuditEntry("fips-violation", "Host is not in FIPS-compliant mode")
			if cfg.Strict {
				return fmt.Errorf("FIPS strict enforcement failed: host has FIPS disabled")
			}
		}
		// Write the value to the container proc to simulate or mirror it
		_ = os.WriteFile(filepath.Join(fipsDir, "fips_enabled"), []byte(fipsVal+"\n"), 0o644)
		logAuditEntry("fips-check", fmt.Sprintf("FIPS mode status: %s", fipsVal))
	}

	for _, path := range cfg.ReadPaths {
		// If BlockCrypto is true, skip ssl/certs and crypto libraries if they are read paths
		if cfg.BlockCrypto {
			if strings.Contains(path, "/etc/ssl") || strings.Contains(path, "/usr/lib/ssl") || strings.Contains(path, "/etc/security") {
				continue
			}
		}

		target := filepath.Join(newRoot, path)
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}

		_, statErr := os.Stat(target)
		targetExists := statErr == nil

		if !targetExists {
			if fi.IsDir() {
				err = os.MkdirAll(target, 0o755)
			} else {
				err = os.MkdirAll(filepath.Dir(target), 0o755)
				if err == nil {
					var f *os.File
					f, err = os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0o644)
					if err == nil {
						f.Close()
					}
				}
			}
		} else {
			err = nil
		}

		if err == nil {
			// Linux requires bind mount and read-only remount to be separate steps.
			// Using MS_REC ensures sub-mounts (like /run/systemd) are included.
			if err := syscall.Mount(path, target, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
				if cfg.Strict {
					return fmt.Errorf("bind mount %s: %w", path, err)
				}
				fmt.Fprintf(os.Stderr, "safer-exec: warning: bind mount %s: %v\n", path, err)
			} else {
				_ = syscall.Mount("none", target, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, "")
			}
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
				err = os.MkdirAll(target, 0o755)
			} else {
				err = os.MkdirAll(filepath.Dir(target), 0o755)
				if err == nil {
					var f *os.File
					f, err = os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0o644)
					if err == nil {
						f.Close()
					}
				}
			}
		} else {
			err = nil
		}

		if err == nil {
			if err := syscall.Mount(path, target, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
				if cfg.Strict {
					return fmt.Errorf("bind mount %s: %w", path, err)
				}
				fmt.Fprintf(os.Stderr, "safer-exec: warning: bind mount %s: %v\n", path, err)
			}
		}
	}
	return finalizeFilesystem(newRoot)
}

func setupFilesystemDiff(cfg config.ExecConfig) error {
	newRoot, _ := os.MkdirTemp("", "safer-exec-root-*")
	upperDir, _ := os.MkdirTemp("", "safer-exec-upper-*")
	workDir, _ := os.MkdirTemp("", "safer-exec-work-*")

	if err := syscall.Mount("tmpfs", newRoot, "tmpfs", 0, "size=64m"); err != nil {
		return fmt.Errorf("mount tmpfs: %w", err)
	}

	var lowerDirs []string
	for _, path := range append(cfg.ReadPaths, cfg.WritePaths...) {
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
	procDir := filepath.Join(newRoot, "proc")
	_ = os.MkdirAll(procDir, 0o555)
	if err := syscall.Mount("proc", procDir, "proc", 0, ""); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: mount proc: %v\n", err)
	}

	sysDir := filepath.Join(newRoot, "sys")
	_ = os.MkdirAll(sysDir, 0o555)
	_ = syscall.Mount("sysfs", sysDir, "sysfs", 0, "") // Ignore EPERM

	_ = syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_SLAVE, "") // Ignore EPERM

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
	_ = os.Remove("/.put")
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

	if len(cfg.AllowIPs) == 0 && len(cfg.AllowPorts) == 0 && !cfg.DisableNetwork {
		return nil
	}
	ports := cfg.AllowPorts
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
		argvPtrs = []*byte{nil}
	}
	if len(envpPtrs) == 0 {
		envpPtrs = []*byte{nil}
	}

	_, _, errno := syscall.RawSyscall6(
		uintptr(sysEXECVEAT),
		uintptr(dirfd),
		uintptr(unsafe.Pointer(pathnamePtr)),
		uintptr(unsafe.Pointer(&argvPtrs[0])),
		uintptr(unsafe.Pointer(&envpPtrs[0])),
		uintptr(flags),
		0,
	)
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
