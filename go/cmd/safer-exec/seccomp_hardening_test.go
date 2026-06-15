//go:build linux

package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// seccompResult is the action returned by evaluating the BPF program.
type seccompResult uint32

// evalSeccomp is a minimal classic-BPF interpreter covering exactly the opcodes
// buildSeccompProgram emits (LD W ABS, JEQ, JSET, AND, RET). It evaluates the
// program against a synthetic struct seccomp_data and returns the RET value, so
// tests can assert the filter's decision for a given (arch, nr, args) tuple
// without ever loading the filter into the kernel.
func evalSeccomp(t *testing.T, prog []syscall.SockFilter, arch uint32, nr uint32, args [6]uint64) seccompResult {
	t.Helper()

	// struct seccomp_data: nr(0), arch(4), instruction_pointer(8), args[6](16..).
	data := make([]byte, 16+6*8)
	binary.LittleEndian.PutUint32(data[0:], nr)
	binary.LittleEndian.PutUint32(data[4:], arch)
	for i, a := range args {
		binary.LittleEndian.PutUint64(data[16+i*8:], a)
	}
	loadWord := func(off uint32) uint32 {
		if int(off)+4 > len(data) {
			return 0
		}
		return binary.LittleEndian.Uint32(data[off:])
	}

	var a uint32
	for pc := 0; pc < len(prog); {
		ins := prog[pc]
		switch ins.Code {
		case bpfLoadWordAbsolute:
			a = loadWord(ins.K)
			pc++
		case bpfAluAnd:
			a &= ins.K
			pc++
		case bpfJmpEq:
			if a == ins.K {
				pc += 1 + int(ins.Jt)
			} else {
				pc += 1 + int(ins.Jf)
			}
		case bpfJmpSet:
			if a&ins.K != 0 {
				pc += 1 + int(ins.Jt)
			} else {
				pc += 1 + int(ins.Jf)
			}
		case bpfJmpReturn:
			return seccompResult(ins.K)
		default:
			t.Fatalf("evalSeccomp: unsupported opcode 0x%x at pc %d", ins.Code, pc)
		}
	}
	t.Fatalf("evalSeccomp: program fell through without a RET")
	return 0
}

const (
	resAllow       = seccompResult(seccompRetAllow)
	resKillProcess = seccompResult(seccompRetKillProcess)
	resKillThread  = seccompResult(seccompRetKill)
)

func resErrno(e syscall.Errno) seccompResult {
	return seccompResult(uint32(seccompRetErrno) | uint32(e))
}

func cloneArgs(flags uint64) [6]uint64 { return [6]uint64{flags} }

func TestSeccomp_ArchPinning(t *testing.T) {
	prog := buildSeccompProgram(config.ExecConfig{})

	// Native arch + a benign syscall is allowed.
	if got := evalSeccomp(t, prog, seccompAuditArch, syscall.SYS_READ, [6]uint64{}); got != resAllow {
		t.Fatalf("native read: got %#x, want ALLOW", uint32(got))
	}

	// A foreign architecture (e.g. the i386 compat gate, AUDIT_ARCH_I386) is
	// killed regardless of the syscall number — this is the core C-1 defense.
	const auditArchI386 = 0x40000003
	if got := evalSeccomp(t, prog, auditArchI386, syscall.SYS_READ, [6]uint64{}); got != resKillProcess {
		t.Fatalf("i386 compat read: got %#x, want KILL_PROCESS", uint32(got))
	}
	// Even a syscall that is otherwise allowed under the native arch is killed
	// when it arrives under a foreign arch.
	if got := evalSeccomp(t, prog, auditArchI386, 26 /* i386 ptrace */, [6]uint64{}); got != resKillProcess {
		t.Fatalf("i386 ptrace: got %#x, want KILL_PROCESS", uint32(got))
	}
}

func TestSeccomp_X32Rejected(t *testing.T) {
	if seccompX32SyscallBit == 0 {
		t.Skip("no x32 ABI on this architecture")
	}
	prog := buildSeccompProgram(config.ExecConfig{})
	// An x32 syscall number carries __X32_SYSCALL_BIT and shares
	// AUDIT_ARCH_X86_64, so only the dedicated bit check catches it.
	nr := uint32(syscall.SYS_READ) | uint32(seccompX32SyscallBit)
	if got := evalSeccomp(t, prog, seccompAuditArch, nr, [6]uint64{}); got != resKillProcess {
		t.Fatalf("x32 read: got %#x, want KILL_PROCESS", uint32(got))
	}
}

func TestSeccomp_DefaultBlocklist(t *testing.T) {
	prog := buildSeccompProgram(config.ExecConfig{})
	for _, nr := range []uintptr{syscall.SYS_PTRACE, syscall.SYS_MOUNT, syscall.SYS_UNSHARE, syscall.SYS_PIVOT_ROOT, syscall.SYS_SETUID, syscall.SYS_CHROOT} {
		if got := evalSeccomp(t, prog, seccompAuditArch, uint32(nr), [6]uint64{}); got != resErrno(syscall.EPERM) {
			t.Fatalf("blocked syscall %d: got %#x, want EPERM", nr, uint32(got))
		}
	}
}

func TestSeccomp_Clone3ForcedENOSYS(t *testing.T) {
	if sysCLONE3 == 9999 {
		t.Skip("clone3 not mapped on this architecture")
	}
	// Default config blocks nested userns, so clone3 must be ENOSYS to force the
	// inspectable clone() fallback.
	prog := buildSeccompProgram(config.ExecConfig{})
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(sysCLONE3), [6]uint64{}); got != resErrno(syscall.ENOSYS) {
		t.Fatalf("clone3 (default): got %#x, want ENOSYS", uint32(got))
	}

	// With AllowUserns and no BlockFork there is no clone inspection, so clone3
	// is allowed through.
	progAllow := buildSeccompProgram(config.ExecConfig{AllowUserns: true})
	if got := evalSeccomp(t, progAllow, seccompAuditArch, uint32(sysCLONE3), [6]uint64{}); got != resAllow {
		t.Fatalf("clone3 (AllowUserns): got %#x, want ALLOW", uint32(got))
	}
}

func TestSeccomp_NestedUsernsBlocked(t *testing.T) {
	prog := buildSeccompProgram(config.ExecConfig{})

	// clone(CLONE_NEWUSER) and clone(CLONE_NEWNS) are denied with EPERM.
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(syscall.SYS_CLONE), cloneArgs(cloneNewUserFlag)); got != resErrno(syscall.EPERM) {
		t.Fatalf("clone CLONE_NEWUSER: got %#x, want EPERM", uint32(got))
	}
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(syscall.SYS_CLONE), cloneArgs(cloneNewNSFlag)); got != resErrno(syscall.EPERM) {
		t.Fatalf("clone CLONE_NEWNS: got %#x, want EPERM", uint32(got))
	}
	// A plain thread/process clone with neither namespace flag is allowed (the
	// process is not forking namespaces; fork-blocking is governed separately).
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(syscall.SYS_CLONE), cloneArgs(0x10f00 /* CLONE_VM|... thread-ish */)); got != resAllow {
		t.Fatalf("clone (no ns flags): got %#x, want ALLOW", uint32(got))
	}

	// Opt-out restores the ability to create nested namespaces.
	progAllow := buildSeccompProgram(config.ExecConfig{AllowUserns: true})
	if got := evalSeccomp(t, progAllow, seccompAuditArch, uint32(syscall.SYS_CLONE), cloneArgs(cloneNewUserFlag)); got != resAllow {
		t.Fatalf("clone CLONE_NEWUSER (AllowUserns): got %#x, want ALLOW", uint32(got))
	}
}

func TestSeccomp_BlockForkAllowsThreads(t *testing.T) {
	prog := buildSeccompProgram(config.ExecConfig{BlockFork: true})

	// Thread creation (CLONE_THREAD) must survive so runtimes can start.
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(syscall.SYS_CLONE), cloneArgs(cloneThreadFlag)); got != resAllow {
		t.Fatalf("clone CLONE_THREAD: got %#x, want ALLOW", uint32(got))
	}
	// A genuine process fork via clone (no CLONE_THREAD) is killed.
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(syscall.SYS_CLONE), cloneArgs(0)); got != resKillThread {
		t.Fatalf("clone process-fork: got %#x, want KILL", uint32(got))
	}
	// fork()/vfork() (where they exist) are denied with EPERM.
	if sysFORK != 9999 {
		if got := evalSeccomp(t, prog, seccompAuditArch, uint32(sysFORK), [6]uint64{}); got != resErrno(syscall.EPERM) {
			t.Fatalf("fork: got %#x, want EPERM", uint32(got))
		}
	}
	// NEWUSER is still blocked even when the primary intent is fork-blocking.
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(syscall.SYS_CLONE), cloneArgs(cloneNewUserFlag)); got != resErrno(syscall.EPERM) {
		t.Fatalf("clone CLONE_NEWUSER under BlockFork: got %#x, want EPERM", uint32(got))
	}
}

func TestSeccomp_BlockExecWildcard(t *testing.T) {
	if sysEXECVEAT == 9999 {
		t.Skip("execveat not mapped on this architecture")
	}

	// With blockFork: no children can exist, so execve stays open for the
	// launcher and the execveat evasion vector is blocked.
	withFork := buildSeccompProgram(config.ExecConfig{BlockExec: []string{"*"}, BlockFork: true})
	if got := evalSeccomp(t, withFork, seccompAuditArch, uint32(syscall.SYS_EXECVE), [6]uint64{}); got != resAllow {
		t.Fatalf("execve (wildcard+blockFork): got %#x, want ALLOW (launcher path)", uint32(got))
	}
	if got := evalSeccomp(t, withFork, seccompAuditArch, uint32(sysEXECVEAT), [6]uint64{}); got != resErrno(syscall.EPERM) {
		t.Fatalf("execveat (wildcard+blockFork): got %#x, want EPERM", uint32(got))
	}

	// Without blockFork: children can exist, so the libc execve path is blocked.
	noFork := buildSeccompProgram(config.ExecConfig{BlockExec: []string{"*"}})
	if got := evalSeccomp(t, noFork, seccompAuditArch, uint32(syscall.SYS_EXECVE), [6]uint64{}); got != resErrno(syscall.EPERM) {
		t.Fatalf("execve (wildcard, no blockFork): got %#x, want EPERM", uint32(got))
	}
}

func TestSeccomp_TraceExecDoesNotBlock(t *testing.T) {
	// traceExec must observe, not block: neither exec syscall is filtered.
	prog := buildSeccompProgram(config.ExecConfig{TraceExec: true})
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(syscall.SYS_EXECVE), [6]uint64{}); got != resAllow {
		t.Fatalf("execve (traceExec): got %#x, want ALLOW", uint32(got))
	}
	if sysEXECVEAT != 9999 {
		if got := evalSeccomp(t, prog, seccompAuditArch, uint32(sysEXECVEAT), [6]uint64{}); got != resAllow {
			t.Fatalf("execveat (traceExec): got %#x, want ALLOW", uint32(got))
		}
	}
}

func TestPrepareExecEnv_NonFatalErrors(t *testing.T) {
	// An unresolved command is not a setup failure: it must fall back to the raw
	// name and return a nil error (the kernel reports ENOENT at exec time). A
	// regression here means a non-fatal lookup/extraction error leaks through the
	// named return and aborts the whole sandboxed run.
	cmdPath, _, _, cleanup, err := prepareExecEnv(config.ExecConfig{Cmd: "safer-exec-no-such-cmd-xyz"})
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatalf("unresolved command returned a fatal error: %v", err)
	}
	if cmdPath != "safer-exec-no-such-cmd-xyz" {
		t.Errorf("cmdPath = %q, want fallback to the raw command name", cmdPath)
	}

	// Enabling library tracing must not turn a helper-extraction problem into a
	// fatal error; preparation still succeeds (tracing simply degrades).
	_, _, _, cleanup2, err := prepareExecEnv(config.ExecConfig{Cmd: "sh", TraceLibraries: true})
	if cleanup2 != nil {
		defer cleanup2()
	}
	if err != nil {
		t.Fatalf("TraceLibraries preparation returned a fatal error: %v", err)
	}
}

func TestExtractPrecompiledAuditHelper_BespokeTempDir(t *testing.T) {
	if !hasPrecompiledSo || len(auditHelperSo) == 0 {
		t.Skip("no precompiled audit helper embedded for this platform")
	}
	// Passing "" must create a bespoke, writable temp directory under the system
	// temp location and extract the helper there, independent of the working
	// directory or CI temp env vars (the reduced-mode CI failure mode).
	p, err := extractPrecompiledAuditHelper("")
	if err != nil {
		t.Fatalf("extraction to bespoke temp dir failed: %v", err)
	}
	defer os.RemoveAll(filepath.Dir(p))
	if !strings.HasPrefix(p, os.TempDir()) {
		t.Errorf("helper %q not under system temp dir %q", p, os.TempDir())
	}
	fi, statErr := os.Stat(p)
	if statErr != nil || fi.Size() == 0 {
		t.Fatalf("extracted helper missing or empty: stat err=%v", statErr)
	}
}

func TestProvisionAuditHelperDir(t *testing.T) {
	if isMusl() || !hasPrecompiledSo || len(auditHelperSo) == 0 {
		t.Skip("library tracing helper not applicable on this platform")
	}

	// When tracing needs the helper and no TraceTempDir is set, a bespoke
	// writable temp dir is created, recorded in TraceTempDir, and registered in
	// WritePaths so Landlock (applied before extraction) permits it.
	cfg := config.ExecConfig{TraceLibraries: true}
	cleanup := provisionAuditHelperDir(&cfg)
	if cfg.TraceTempDir == "" {
		t.Fatal("TraceTempDir was not set")
	}
	if !strings.HasPrefix(cfg.TraceTempDir, os.TempDir()) {
		t.Errorf("helper dir %q not under system temp dir %q", cfg.TraceTempDir, os.TempDir())
	}
	if _, err := os.Stat(cfg.TraceTempDir); err != nil {
		t.Fatalf("helper dir not created: %v", err)
	}
	registered := false
	for _, w := range cfg.WritePaths {
		if w == cfg.TraceTempDir {
			registered = true
		}
	}
	if !registered {
		t.Errorf("helper dir not added to WritePaths: %v", cfg.WritePaths)
	}
	dir := cfg.TraceTempDir
	cleanup()
	if _, err := os.Stat(dir); err == nil {
		t.Errorf("cleanup did not remove helper dir %q", dir)
	}

	// No-op when a TraceTempDir is already provided.
	preset := config.ExecConfig{TraceLibraries: true, TraceTempDir: "/preset"}
	n := len(preset.WritePaths)
	provisionAuditHelperDir(&preset)()
	if preset.TraceTempDir != "/preset" || len(preset.WritePaths) != n {
		t.Error("should be a no-op when TraceTempDir is preset")
	}

	// No-op when library tracing is disabled.
	off := config.ExecConfig{}
	provisionAuditHelperDir(&off)()
	if off.TraceTempDir != "" {
		t.Error("should be a no-op when TraceLibraries is off")
	}
}

func TestPrepareExecEnv_BlockExecIsFatal(t *testing.T) {
	// A blockExec match is the one genuine fatal setup condition.
	if _, _, _, _, err := prepareExecEnv(config.ExecConfig{Cmd: "sh", BlockExec: []string{"sh"}}); err == nil {
		t.Fatalf("blockExec match should return a fatal error")
	}
}

func TestLookTrustedTool(t *testing.T) {
	// A name containing a slash is rejected (must be a bare tool name).
	if got := lookTrustedTool("/usr/bin/unshare"); got != "" {
		t.Errorf("path with slash: got %q, want \"\"", got)
	}
	if got := lookTrustedTool(""); got != "" {
		t.Errorf("empty name: got %q, want \"\"", got)
	}
	// A clearly non-existent tool resolves to nothing.
	if got := lookTrustedTool("safer-exec-no-such-tool-xyz"); got != "" {
		t.Errorf("missing tool: got %q, want \"\"", got)
	}
	// A core utility present on essentially every Linux system must resolve to an
	// absolute path inside one of the trusted directories — never via $PATH.
	if got := lookTrustedTool("env"); got != "" {
		inTrusted := false
		for _, dir := range trustedSystemDirs {
			if strings.HasPrefix(got, dir+"/") {
				inTrusted = true
				break
			}
		}
		if !inTrusted {
			t.Errorf("env resolved outside trusted dirs: %q", got)
		}
	}
}

func TestUnescapeMountField(t *testing.T) {
	cases := map[string]string{
		`/mnt/plain`:         `/mnt/plain`,
		`/mnt/with\040space`: `/mnt/with space`,
		`/mnt/tab\011here`:   "/mnt/tab\there",
		`/mnt/back\134slash`: `/mnt/back\slash`,
		`/a\040b/c\040d`:     `/a b/c d`,
		`\040leading`:        ` leading`,
		`/no/escapes/at/all`: `/no/escapes/at/all`,
	}
	for in, want := range cases {
		if got := unescapeMountField(in); got != want {
			t.Errorf("unescapeMountField(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSeccomp_BlockJIT_Mprotect(t *testing.T) {
	prog := buildSeccompProgram(config.ExecConfig{BlockJIT: true})

	// mprotect adding PROT_EXEC is denied.
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(syscall.SYS_MPROTECT), [6]uint64{0, 0, protExec}); got != resErrno(syscall.EPERM) {
		t.Errorf("mprotect(PROT_EXEC): got %#x, want EPERM", uint32(got))
	}
	// pkey_mprotect adding PROT_EXEC is denied.
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(sysPKEY_MPROTECT), [6]uint64{0, 0, protExec}); got != resErrno(syscall.EPERM) {
		t.Errorf("pkey_mprotect(PROT_EXEC): got %#x, want EPERM", uint32(got))
	}
	// mprotect without PROT_EXEC (e.g. making memory read-only) is allowed.
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(syscall.SYS_MPROTECT), [6]uint64{0, 0, protWrite}); got != resAllow {
		t.Errorf("mprotect(PROT_WRITE): got %#x, want ALLOW", uint32(got))
	}
}

func TestSeccomp_BlockJIT_Mmap(t *testing.T) {
	prog := buildSeccompProgram(config.ExecConfig{BlockJIT: true})

	// W+X mmap is denied.
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(syscall.SYS_MMAP), [6]uint64{0, 0, protWrite | protExec}); got != resErrno(syscall.EPERM) {
		t.Errorf("mmap(PROT_WRITE|PROT_EXEC): got %#x, want EPERM", uint32(got))
	}
	// Write-only mmap (the common case) is allowed.
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(syscall.SYS_MMAP), [6]uint64{0, 0, protWrite}); got != resAllow {
		t.Errorf("mmap(PROT_WRITE): got %#x, want ALLOW", uint32(got))
	}
	// Exec-only mmap (mapping a signed library) is allowed.
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(syscall.SYS_MMAP), [6]uint64{0, 0, protExec}); got != resAllow {
		t.Errorf("mmap(PROT_EXEC): got %#x, want ALLOW", uint32(got))
	}
}

func TestSeccomp_BlockJIT_MemfdCreate(t *testing.T) {
	prog := buildSeccompProgram(config.ExecConfig{BlockJIT: true})
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(sysMEMFD_CREATE), [6]uint64{}); got != resErrno(syscall.EPERM) {
		t.Errorf("memfd_create: got %#x, want EPERM", uint32(got))
	}
}

func TestSeccomp_BlockJIT_Disabled(t *testing.T) {
	// Without BlockJIT, the W+X paths are not filtered.
	prog := buildSeccompProgram(config.ExecConfig{})
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(syscall.SYS_MPROTECT), [6]uint64{0, 0, protExec}); got != resAllow {
		t.Errorf("mprotect(PROT_EXEC) without BlockJIT: got %#x, want ALLOW", uint32(got))
	}
	if got := evalSeccomp(t, prog, seccompAuditArch, uint32(syscall.SYS_MMAP), [6]uint64{0, 0, protWrite | protExec}); got != resAllow {
		t.Errorf("mmap(W|X) without BlockJIT: got %#x, want ALLOW", uint32(got))
	}
}
