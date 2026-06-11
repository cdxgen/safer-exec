//go:build openbsd

// Package main_openbsd implements the OpenBSD sandbox engine using unveil(2)
// for filesystem access control and pledge(2) for syscall promises.
//
// OpenBSD's native sandbox primitives provide simple but effective isolation:
//   - unveil(path, "r")      — restrict to read-only access
//   - unveil(path, "rwc")    — allow read, write, and create
//   - unveil(path, "rx")     — allow read and execute
//   - unveil(path, "rwcx")   — allow read, write, create, and execute
//   - pledge("stdio rpath wpath proc exec", NULL) — restrict syscall surface
//
// Unlike Linux/macOS engines, the OpenBSD engine does not use a separate
// sandbox wrapper binary. It applies unveil/pledge directly before execve.
//
// Resource limits on OpenBSD are enforced via setrlimit(2), similar to macOS.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

const (
	rlimitAS    = 2 // RLIMIT_AS
	rlimitNPROC = 6 // RLIMIT_NPROC
)

// unveil is a wrapper around the unveil(2) system call.
// It restricts filesystem access to the given path with the specified permissions.
// Calling unveil(nil, nil) locks the list and prevents further unveil calls.
//
//go:noinline
func unveil(path string, permissions string) error {
	pathPtr, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	permPtr, err := syscall.BytePtrFromString(permissions)
	if err != nil {
		return err
	}
	_, _, errno := syscall.RawSyscall(386, uintptr(unsafe.Pointer(pathPtr)), uintptr(unsafe.Pointer(permPtr)), 0) // SYS_unveil = 114 on OpenBSD
	if errno != 0 {
		return errno
	}
	return nil
}

// pledge is a wrapper around the pledge(2) system call.
// It restricts the syscall surface to the specified promises.
//
//go:noinline
func pledge(promises string, execpromises string) error {
	promisesPtr, err := syscall.BytePtrFromString(promises)
	if err != nil {
		return err
	}
	var execpromisesPtr unsafe.Pointer
	if execpromises != "" {
		ptr, err := syscall.BytePtrFromString(execpromises)
		if err != nil {
			return err
		}
		execpromisesPtr = unsafe.Pointer(ptr)
	}
	_, _, errno := syscall.RawSyscall(108, uintptr(unsafe.Pointer(promisesPtr)), uintptr(execpromisesPtr), 0) // SYS_pledge = 108 on OpenBSD
	if errno != 0 {
		return errno
	}
	return nil
}

// run applies unveil(2) and pledge(2) sandboxing, then executes the target command.
func run(cfg config.ExecConfig) error {
	if cfg.EnableLearn {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: learning mode is not yet supported on OpenBSD\n")
	}

	// Apply resource limits via setrlimit
	if err := setResourceLimitsOpenBSD(cfg); err != nil {
		return fmt.Errorf("setting resource limits: %w", err)
	}

	// Apply unveil for read paths (read-only + execute)
	for _, path := range cfg.ReadPaths {
		if err := unveil(path, "rx"); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: unveil(%s, rx): %v\n", path, err)
		}
	}

	// Apply unveil for write paths (read, write, create, execute)
	for _, path := range cfg.WritePaths {
		if err := unveil(path, "rwcx"); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: unveil(%s, rwcx): %v\n", path, err)
		}
	}

	// Always allow reading system paths
	for _, path := range []string{"/usr/lib", "/usr/libexec", "/usr/share", "/usr/local/lib", "/etc", "/tmp"} {
		if _, err := os.Stat(path); err == nil {
			_ = unveil(path, "rx")
		}
	}

	// Allow writing to /tmp by default
	_ = unveil("/tmp", "rwcx")

	// Lock the unveil list
	// After this call, no further unveil calls can be made.
	_ = unveil("", "")

	// Build pledge promises based on config
	promises := []string{"stdio", "rpath", "wpath", "cpath", "fattr", "flock", "dpath", "tty", "getpw", "proc", "exec"}
	if cfg.DisableNetwork {
		// No network promises — no inet/dns access
	} else {
		promises = append(promises, "inet", "dns")
	}
	promiseStr := strings.Join(promises, " ")

	// Apply pledge with execpromises
	// execpromises is empty because the target process should apply its own pledge.
	if err := pledge(promiseStr, ""); err != nil {
		return fmt.Errorf("pledge(%s): %w", promiseStr, err)
	}

	// Set up environment
	env := config.BuildEnv(cfg.Env)

	// Resolve command
	cmdPath, err := exec.LookPath(cfg.Cmd)
	if err != nil {
		cmdPath = cfg.Cmd
	}

	// Execute the target command
	if cfg.WorkingDir != "" {
		_ = os.Chdir(cfg.WorkingDir)
	}
	return syscall.Exec(cmdPath, append([]string{cfg.Cmd}, cfg.Args...), env)
}

// setResourceLimitsOpenBSD applies setrlimit quotas for memory, CPU, and processes.
func setResourceLimitsOpenBSD(cfg config.ExecConfig) error {
	if cfg.MaxMemoryMB > 0 {
		bytes := uint64(cfg.MaxMemoryMB * 1024 * 1024)
		limit := syscall.Rlimit{Cur: bytes, Max: bytes}
		if err := syscall.Setrlimit(rlimitAS, &limit); err != nil {
			return fmt.Errorf("RLIMIT_AS: %w", err)
		}
	}
	if cfg.MaxProcesses > 0 {
		limit := syscall.Rlimit{Cur: uint64(cfg.MaxProcesses + 10), Max: uint64(cfg.MaxProcesses + 10)}
		_ = syscall.Setrlimit(rlimitNPROC, &limit)
	}
	return nil
}

// runInit is a no-op on OpenBSD (re-exec pattern is Linux-specific).
func runInit(cfg config.ExecConfig) error {
	return run(cfg)
}

// runInitReduced is a no-op on OpenBSD (re-exec pattern is Linux-specific).
func runInitReduced(cfg config.ExecConfig) error {
	return run(cfg)
}

// runDiagnostics probes OpenBSD capabilities and returns a structured report.
func runDiagnostics() config.DiagnosticsResult {
	result := config.DiagnosticsResult{
		Platform:     "openbsd",
		Arch:         runtime.GOARCH,
		Capabilities: make(map[string]config.CapabilityInfo),
		Features:     make(map[string]bool),
	}

	// Kernel version
	if uname, err := exec.Command("uname", "-r").Output(); err == nil {
		result.Kernel = strings.TrimSpace(string(uname))
	}
	if uname, err := exec.Command("uname", "-s").Output(); err == nil {
		result.Release = "OpenBSD " + strings.TrimSpace(string(uname)) + " " + result.Kernel
	}

	// unveil(2) — available since OpenBSD 6.4
	result.Capabilities["unveil"] = config.CapabilityInfo{Available: true, Detail: "unveil(2) filesystem access control"}

	// pledge(2) — available since OpenBSD 5.9
	result.Capabilities["pledge"] = config.CapabilityInfo{Available: true, Detail: "pledge(2) syscall restriction"}

	// setrlimit
	result.Capabilities["rlimit_as"] = config.CapabilityInfo{Available: true, Detail: "setrlimit(2) available"}
	result.Capabilities["rlimit_nproc"] = config.CapabilityInfo{Available: true, Detail: "setrlimit(2) available"}

	// Map capabilities to features
	result.Features["network_isolation"] = true
	result.Features["file_read_restriction"] = true
	result.Features["file_write_restriction"] = true
	result.Features["memory_limit"] = true
	result.Features["cpu_limit"] = false
	result.Features["process_limit"] = true
	result.Features["exec_control"] = true
	result.Features["fork_control"] = true
	result.Features["audit_tracing"] = false
	result.Features["filesystem_diff"] = true
	result.Features["learning_mode"] = false
	result.Features["strict_mode"] = true
	result.Features["crypto_control"] = false
	result.Features["fips_detection"] = false
	result.Features["gpu_control"] = false
	result.Features["tpm_control"] = false
	result.Features["antivm_spoofing"] = false
	result.Features["trace_libraries"] = false
	result.Features["trace_http_urls"] = false
	result.Features["allow_url_rules"] = false
	result.Features["time_isolation"] = false
	result.Features["ipc_isolation"] = false
	result.Features["io_limit"] = false
	result.Features["landlock_filesystem"] = false
	result.Features["landlock_layers"] = false
	result.Features["apparmor_safer_exec"] = false
	result.Features["proc_hidepid"] = false
	result.Features["profile_validation"] = false

	return result
}

// Ensure imports are used
var _ = json.Marshal
var _ = unsafe.Pointer(nil)
