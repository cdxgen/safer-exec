//go:build windows

// Windows engine: runs the command in a Microsoft eXecution Container (MXC)
// ProcessContainer through the MXC executor, wxc-exec.exe.
//
// On current Windows 11 builds MXC creates the workload inside an OS
// "BaseContainer" (CreateProcessSecurityEnvironment): the process sees only
// the paths it is granted (plus the read-only Windows directory), its
// outbound traffic is filtered per container by WFP, and Win32k/UI access is
// locked down. The engine:
//
//  1. probes the host (wxc-exec --probe) and refuses the host-ACL-mutating
//     fallback tier unless the caller consented to it;
//  2. starts the egress proxy when hostname pinning (or learning) is needed;
//  3. translates the ExecConfig into an MXC 1.0.0 request (internal/mxc);
//  4. launches wxc-exec.exe inside a job object that carries the memory, CPU
//     and process-count limits — wxc-exec's own job nests under it, so the
//     limits cover the whole workload tree, and closing the job kills it;
//  5. forwards the workload's output while extracting MXC's stderr protocol
//     (error envelope, denial-report pointer);
//  6. emits audit entries, learned policies, dry-run reports and filesystem
//     diffs in the same formats as the macOS and Linux engines, and, with
//     traceLibraries, the DLLs the workload loaded, from an ETW session the
//     engine runs outside the container (internal/dlltrace).
//
// The workload shares wxc-exec's stderr, so nothing read from it is trusted
// on its own: the denial report is read only from the engine's run
// directory, a timeout is confirmed against the engine's own clock, and
// audit and diff output are produced whatever MXC appears to have reported.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/cdxgen/safer-exec/go/internal/config"
	"github.com/cdxgen/safer-exec/go/internal/dlltrace"
	"github.com/cdxgen/safer-exec/go/internal/fsdiff"
	"github.com/cdxgen/safer-exec/go/internal/mxc"
	"github.com/cdxgen/safer-exec/go/internal/winjob"
)

// launcherEnvVar names an explicit wxc-exec.exe to use instead of the copy
// shipped next to the engine.
const launcherEnvVar = "SAFER_EXEC_MXC_EXEC"

// launcherName is the MXC Windows executor.
const launcherName = "wxc-exec.exe"

// timeoutGrace is how long the engine waits past the configured timeout for
// MXC to stop the workload before it terminates the job itself.
const timeoutGrace = 30 * time.Second

// timeoutExitCode matches the macOS engine's timeout exit status.
const timeoutExitCode = 124

// memoryLimitExitCode is the workload's exit status when it exceeds its
// memory limit. Windows job limits make the failing allocation return an
// error instead of killing the process, and runtimes frequently wedge in that
// state (observed: a Go program hangs in process exit after its fatal
// out-of-memory report). The engine therefore applies Linux cgroup OOM-kill
// semantics and terminates the workload, with the status a shell reports for
// SIGKILL.
const memoryLimitExitCode = 137

// writeStructured writes a structured output line (e.g. "FSDIFF:{...}") either
// to the file at cfg.StructuredOutputPath (when set) or to stdout.
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
	fmt.Print(line)
}

// resolveLauncher locates wxc-exec.exe: an explicit absolute path in
// SAFER_EXEC_MXC_EXEC, then the engine's own directory (the npm platform
// package ships it there). PATH is deliberately not searched: wxc-exec runs
// with the user's full privileges, and a PATH directory a previous sandbox
// could write to would let it plant one.
func resolveLauncher() (string, error) {
	if p := os.Getenv(launcherEnvVar); p != "" {
		if !filepath.IsAbs(p) {
			return "", fmt.Errorf("%s must be an absolute path, got %q", launcherEnvVar, p)
		}
		if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
			return "", fmt.Errorf("%s=%q is not a file", launcherEnvVar, p)
		}
		return p, nil
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, c := range []string{filepath.Join(dir, launcherName), filepath.Join(dir, "mxc", launcherName)} {
			if fi, err := os.Stat(c); err == nil && fi.Mode().IsRegular() {
				return c, nil
			}
		}
	}
	return "", fmt.Errorf("the MXC executor %s was not found next to the safer-exec runtime (set %s to its absolute path)", launcherName, launcherEnvVar)
}

// launcherEnv is the environment for wxc-exec.exe itself: the engine's own,
// without MXC's debug and override variables (MXC_FORCE_TIER and friends),
// which could otherwise select a containment tier other than the one the
// probe vetted. The workload never sees this environment; it gets the
// explicit block in the request.
func launcherEnv() []string {
	env := os.Environ()
	out := env[:0:0]
	for _, kv := range env {
		upper := strings.ToUpper(kv)
		if strings.HasPrefix(upper, "MXC_") || strings.HasPrefix(upper, "WXC_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// liveHost describes this machine to the translator.
func liveHost() mxc.Host {
	cwd, _ := os.Getwd()
	return mxc.Host{
		Env: mxc.ParseEnviron(os.Environ()),
		Cwd: cwd,
		IsFile: func(p string) bool {
			fi, err := os.Stat(p)
			return err == nil && fi.Mode().IsRegular()
		},
		Exists: func(p string) bool {
			_, err := os.Stat(p)
			return err == nil
		},
		LookupIP:  net.LookupIP,
		NumCPU:    runtime.NumCPU(),
		LongPath:  longPath,
		Documents: documentsFolder(),
	}
}

// documentsFolder returns the user's Documents folder, which OneDrive and
// folder redirection can move. It reads the shell's User Shell Folders key
// rather than calling SHGetKnownFolderPath, which needs shell32.dll (and
// with it user32.dll) and fails where those cannot initialize.
func documentsFolder() string {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("Personal")
	if err != nil {
		return ""
	}
	if expanded, err := registry.ExpandString(v); err == nil {
		v = expanded
	}
	if !filepath.IsAbs(v) {
		return ""
	}
	return v
}

// longPath expands 8.3 short names in an existing path; it returns path
// unchanged when the expansion fails.
func longPath(path string) string {
	in, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return path
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(in, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return path
	}
	return windows.UTF16ToString(buf[:n])
}

// runRoot is the parent of every run directory. Each request names it as a
// protected path, so no sandbox (this one or a concurrent one with a broad
// TEMP grant) can read another run's request, which carries its environment,
// or rewrite a request or denial report before MXC or the engine reads it.
func runRoot() string {
	return filepath.Join(os.TempDir(), "safer-exec-mxc")
}

// mxcStateDir is where MXC keeps the ACL backups it replays on every start
// (its crash recovery for the ACL-modifying tier). A workload able to write
// there could make the next unsandboxed wxc-exec rewrite arbitrary ACLs.
func mxcStateDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return ""
	}
	return filepath.Join(base, "Microsoft", "MXC")
}

// protectedPaths creates the engine-owned directories (a deny is applied to
// an existing path) and returns them.
func protectedPaths() []string {
	var out []string
	for _, p := range []string{runRoot(), mxcStateDir()} {
		if p == "" {
			continue
		}
		if err := os.MkdirAll(p, 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: create %s: %v\n", p, err)
		}
		// Long names, so the learner compares them with recorded paths.
		out = append(out, longPath(p))
	}
	return out
}

// probeHost runs "wxc-exec --probe", which selects the containment tier
// without starting a sandbox.
func probeHost(launcher string) (*mxc.ProbeResult, error) {
	cmd := exec.Command(launcher, "--probe")
	cmd.Env = launcherEnv()
	out, err := runWithTimeout(cmd, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%s --probe: %w", launcher, err)
	}
	return mxc.ParseProbe(out)
}

func runWithTimeout(cmd *exec.Cmd, d time.Duration) ([]byte, error) {
	var stdout strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return []byte(stdout.String()), err
	case <-time.After(d):
		_ = cmd.Process.Kill()
		<-done
		return nil, fmt.Errorf("timed out after %s", d)
	}
}

// requiresHostLoopback reports whether the direct-egress policy will ask for
// host loopback, which only some container API versions can grant.
func requiresHostLoopback(cfg config.ExecConfig) bool {
	if cfg.AllowLoopback {
		return true
	}
	for _, ip := range cfg.AllowIPs {
		if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil && parsed.IsLoopback() {
			return true
		}
		if _, n, err := net.ParseCIDR(strings.TrimSpace(ip)); err == nil && n.IP.IsLoopback() {
			return true
		}
	}
	return false
}

// run executes cfg.Cmd in an MXC ProcessContainer.
func run(cfg config.ExecConfig) error {
	mode := mxc.ModeEnforce
	switch {
	case cfg.EnableLearn:
		mode = mxc.ModeLearn
	case cfg.EnableDryRun:
		mode = mxc.ModeDryRun
		cfg.EnableAudit = true
	}

	launcher, launcherErr := resolveLauncher()
	if launcherErr != nil && !cfg.DumpProfile {
		return launcherErr
	}

	// Host capability probe: refuse to let MXC rewrite host ACLs unless the
	// caller consented, and learn whether host loopback can be granted.
	var probe *mxc.ProbeResult
	if launcherErr == nil {
		p, err := probeHost(launcher)
		if err != nil {
			if cfg.Strict {
				return err
			}
			fmt.Fprintf(os.Stderr, "safer-exec: warning: %v\n", err)
		} else {
			probe = p
			for _, w := range p.Warnings {
				fmt.Fprintf(os.Stderr, "safer-exec: warning: mxc: %s\n", w)
			}
			if p.MutatesHost() && !cfg.WindowsAllowDaclMutation && !cfg.DumpProfile {
				return fmt.Errorf("this Windows build lacks the BaseContainer API, and MXC's fallback tier (%s) grants access by modifying host file ACLs; "+
					"update Windows (11 24H2 build 26100.9278 / 25H2 build 26200.9278 or later) or consent with windowsAllowDaclMutation", p.Tier)
			}
			if p.Tier != mxc.TierBaseContainer {
				fmt.Fprintf(os.Stderr, "safer-exec: warning: running in MXC's %s containment tier (BaseContainer unavailable)\n", p.Tier)
			}
		}
	}

	handleFIPSWindows(cfg)
	if cfg.StrictFIPS && cfg.Strict && !windowsFIPSEnabled() {
		return errors.New("FIPS strict enforcement failed: the Windows FIPS algorithm policy is disabled")
	}

	locks, err := acquireFileLocks(cfg.LockFiles)
	if err != nil {
		return err
	}
	defer releaseFileLocks(locks)

	protected := protectedPaths()
	workDir, err := os.MkdirTemp(runRoot(), "run-")
	if err != nil {
		return fmt.Errorf("create run directory: %w", err)
	}
	defer os.RemoveAll(workDir)

	// Egress proxy. Learning runs always route through a recording proxy so
	// the learned policy can name hostnames rather than addresses.
	var proxy *egressProxy
	wantProxy := !cfg.DisableNetwork && mode != mxc.ModeDryRun && (mode == mxc.ModeLearn || cfg.ProxyEgress)
	if cfg.DisableNetwork && cfg.ProxyEgress {
		fmt.Fprintln(os.Stderr, "safer-exec: warning: egress proxy skipped: network access is disabled")
	}
	if wantProxy && !cfg.DumpProfile {
		var perr error
		if mode == mxc.ModeLearn {
			proxy, perr = startLearningEgressProxy(cfg)
		} else {
			proxy, perr = startEgressProxy(cfg)
		}
		if perr != nil {
			if cfg.Strict {
				return fmt.Errorf("egress proxy unavailable: %w", perr)
			}
			fmt.Fprintf(os.Stderr, "safer-exec: warning: egress proxy unavailable (%v)\n", perr)
			proxy = nil
		} else {
			defer proxy.Close()
		}
	} else if wantProxy && cfg.DumpProfile {
		// A profile dump shows the proxy shape with a placeholder port.
		proxy = &egressProxy{port: 1}
	}

	opts := mxc.Options{Mode: mode, ProtectedPaths: protected}
	if probe.MutatesHost() {
		opts.CascadingGrants = true
	}
	if proxy != nil {
		opts.ProxyPort = proxy.port
		opts.ProxyEnv = proxy.envVars()
	}
	if mode != mxc.ModeEnforce || cfg.EnableAudit {
		opts.CaptureOutputPath = filepath.Join(workDir, "denials.json")
	}
	if probe != nil && proxy == nil && requiresHostLoopback(cfg) {
		opts.HostLoopbackSupported = probe.Flag("baseContainerSupportsIngressHostLoopbackAllow")
	}

	plan, err := mxc.Translate(cfg, liveHost(), opts)
	if err != nil {
		return err
	}
	for _, w := range plan.Warnings {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: %s\n", w)
	}
	if len(plan.Unenforced) > 0 {
		if cfg.Strict {
			return fmt.Errorf("strict mode: not enforceable on Windows: %s", strings.Join(plan.Unenforced, "; "))
		}
		for _, u := range plan.Unenforced {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: not enforced on Windows: %s\n", u)
		}
	}
	if len(plan.Broadened) > 0 {
		if cfg.Strict {
			return fmt.Errorf("strict mode: Windows would grant more than requested: %s", strings.Join(plan.Broadened, "; "))
		}
		for _, b := range plan.Broadened {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: broader than requested on Windows: %s\n", b)
		}
	}

	request, err := json.MarshalIndent(&plan.Request, "", "  ")
	if err != nil {
		return fmt.Errorf("encode MXC request: %w", err)
	}
	if cfg.DumpProfile {
		writeStructured(cfg, "PROFILE:", request)
		return nil
	}
	requestPath := filepath.Join(workDir, "request.json")
	if err := os.WriteFile(requestPath, request, 0o600); err != nil {
		return fmt.Errorf("write MXC request: %w", err)
	}
	if cfg.ValidateProfile {
		return validateRequest(cfg, launcher, requestPath, string(request))
	}
	if proxy != nil {
		if mode == mxc.ModeLearn {
			fmt.Fprintf(os.Stderr, "safer-exec: learning egress proxy listening on 127.0.0.1:%d; the container can reach only this endpoint, which forwards to any public host and records it\n", proxy.port)
		} else {
			fmt.Fprintf(os.Stderr, "safer-exec: egress proxy listening on 127.0.0.1:%d; outbound traffic is confined to it and hostnames are enforced at CONNECT time\n", proxy.port)
		}
	}

	var before fsdiff.Snapshot
	var snapper *fsdiff.Snapshotter
	if cfg.EnableDiff && len(plan.WritePaths) > 0 && mode == mxc.ModeEnforce {
		snapper, err = fsdiff.NewSnapshotter(plan.WritePaths...)
		if err == nil {
			before, err = snapper.Snapshot()
		}
		if err != nil {
			snapper = nil
			fmt.Fprintf(os.Stderr, "safer-exec: warning: pre-snapshot: %v\n", err)
		}
	}

	limits := winjob.Limits{
		MemoryBytes:     plan.Limits.MemoryBytes,
		CPURate:         plan.Limits.CPURate,
		ActiveProcesses: plan.Limits.ActiveProcesses,
	}
	job, err := winjob.New(limits)
	if err != nil {
		if cfg.Strict || limits != (winjob.Limits{}) {
			return fmt.Errorf("create job object: %w", err)
		}
		fmt.Fprintf(os.Stderr, "safer-exec: warning: create job object: %v; the workload will not be killed if safer-exec exits abnormally\n", err)
		job = nil
	}
	if job != nil {
		defer job.Close()
	}

	// Library tracing needs its ETW session running before wxc-exec starts,
	// so even the workload's first DLLs are recorded.
	var libTrace *dlltrace.Session
	if cfg.TraceLibraries {
		libTrace, err = dlltrace.Start()
		if err != nil {
			if cfg.Strict {
				return fmt.Errorf("traceLibraries: %w", err)
			}
			fmt.Fprintf(os.Stderr, "safer-exec: warning: traceLibraries: %v; no lib-load entries will be reported\n", err)
			libTrace = nil
		} else {
			defer libTrace.Stop()
		}
	}

	stderr := mxc.NewStderrFilter(os.Stderr)
	cmd := exec.Command(launcher, "--config", requestPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = stderr
	cmd.Env = launcherEnv()

	// Console Ctrl+C reaches wxc-exec and the workload directly; the engine
	// must outlive them to collect the result.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer func() {
		signal.Stop(sigCh)
		close(sigCh)
	}()
	go func() {
		for range sigCh {
		}
	}()

	if job != nil {
		err = job.Start(cmd)
	} else {
		err = cmd.Start()
	}
	if err != nil {
		return fmt.Errorf("start %s: %w", launcher, err)
	}
	launcherPID := uint32(cmd.Process.Pid)

	started := time.Now()
	var events sync.WaitGroup
	var memoryKilled atomic.Bool
	// workloadStarted records whether any process other than wxc-exec (and
	// its console host) ever ran in the job. Without a job the engine cannot
	// tell, and assumes it did.
	var workloadStarted atomic.Bool
	workloadStarted.Store(job == nil)
	if job != nil {
		onMemoryLimit := func() {
			if memoryKilled.CompareAndSwap(false, true) {
				// Kill the workload but not wxc-exec, so MXC observes the exit
				// and tears the container down normally.
				_ = job.TerminateExcept(launcherPID, memoryLimitExitCode)
			}
		}
		events.Add(1)
		go func() {
			defer events.Done()
			consumeJobEvents(cfg, job, launcherPID, stderr, onMemoryLimit, &workloadStarted)
		}()
	}

	var backstopFired atomic.Bool
	var backstop *time.Timer
	if cfg.TimeoutMs > 0 {
		deadline := time.Duration(cfg.TimeoutMs)*time.Millisecond + timeoutGrace
		backstop = time.AfterFunc(deadline, func() {
			backstopFired.Store(true)
			if job != nil {
				_ = job.Terminate(timeoutExitCode)
			} else {
				_ = cmd.Process.Kill()
			}
		})
	}

	waitErr := cmd.Wait()
	if backstop != nil {
		backstop.Stop()
	}
	elapsed := time.Since(started)
	_ = stderr.Close()
	var exitErr *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exitErr) {
		return fmt.Errorf("wait for %s: %w", launcher, waitErr)
	}
	exitCode := int(uint32(cmd.ProcessState.ExitCode()))

	if job != nil {
		// Closing the job kills anything the workload left running, which
		// also ends the event stream.
		_ = job.Close()
		events.Wait()
		if n := job.Dropped(); n > 0 {
			stderr.EnsureNewline()
			fmt.Fprintf(os.Stderr, "safer-exec: warning: %d job notifications were dropped; traceExec and limit reports may be incomplete\n", n)
		}
	}
	if memoryKilled.Load() {
		stderr.EnsureNewline()
		fmt.Fprintf(os.Stderr, "safer-exec: warning: the workload exceeded its memory limit (%d MB) and was terminated\n", cfg.MaxMemoryMB)
		exitCode = memoryLimitExitCode
	}
	if proxy != nil && mode != mxc.ModeLearn {
		stderr.EnsureNewline()
		proxy.flushViolations()
	}
	if libTrace != nil {
		emitLibraryLoads(libTrace, launcherPID, stderr)
	}

	// MXC prints an error envelope only when it fails, and then exits
	// non-zero. The workload can print a look-alike, so an envelope is
	// believed only with a non-zero exit, and a timeout only when the
	// engine's own clock agrees.
	envelope := stderr.Envelope()
	if exitCode == 0 {
		envelope = nil
	}
	timeoutElapsed := cfg.TimeoutMs > 0 && elapsed >= time.Duration(cfg.TimeoutMs)*time.Millisecond
	timedOut := backstopFired.Load() ||
		(timeoutElapsed && (envelope.IsTimeout() || exitCode == mxcTimeoutExitCode))
	if envelope.IsTimeout() && !timedOut {
		envelope = nil // a forged timeout report
	}

	// emitResults writes the audit and diff for an enforced run. It runs on
	// every enforce-mode exit path, so neither a forged envelope nor a
	// failure can suppress the record of what the workload did.
	emitResults := func() {
		if mode != mxc.ModeEnforce {
			return
		}
		if cfg.EnableAudit {
			collectAudit(cfg, stderr, workDir, plan.SystemRoot)
		}
		if snapper != nil {
			if after, err := snapper.Snapshot(); err != nil {
				fmt.Fprintf(os.Stderr, "safer-exec: warning: post-snapshot: %v\n", err)
			} else {
				data, _ := json.Marshal(fsdiff.Diff(before, after))
				writeStructured(cfg, "FSDIFF:", data)
			}
		}
	}

	switch {
	case !workloadStarted.Load() && exitCode != 0:
		// wxc-exec failed before any workload process existed: a request
		// rejection or a container start failure, never the workload's own
		// exit status.
		if envelope != nil {
			return mxcFailure(cfg, envelope)
		}
		return fmt.Errorf("windows sandbox: MXC exited with status %d before starting the workload; see its message above", exitCode)
	case timedOut:
		if mode == mxc.ModeEnforce {
			emitResults()
			return &ExitError{Code: timeoutExitCode}
		}
	case envelope != nil && !memoryKilled.Load():
		// A workload killed for exceeding its memory limit already reported
		// why; any MXC diagnostic about its abnormal exit is a consequence.
		emitResults()
		return mxcFailure(cfg, envelope)
	}

	switch mode {
	case mxc.ModeLearn:
		return finishLearn(cfg, plan, workDir, proxy, protected)
	case mxc.ModeDryRun:
		report := readCaptureReport(workDir, plan.SystemRoot)
		result := buildDryRunResult(report.DryRunEvents(), cfg.Cmd, cfg.Args)
		data, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("marshaling dry-run result: %w", err)
		}
		writeStructured(cfg, "DRYRUN:", data)
		return nil
	}

	emitResults()
	if exitCode != 0 {
		return &ExitError{Code: exitCode}
	}
	return nil
}

// mxcTimeoutExitCode is wxc-exec's exit status when MXC's own timer stopped
// the workload (-1 as an unsigned exit code).
const mxcTimeoutExitCode = 0xFFFFFFFF

// mxcFailure turns MXC's error envelope into the engine's error, replacing
// MXC's generic advice where safer-exec knows the actual cause.
func mxcFailure(cfg config.ExecConfig, env *mxc.Envelope) error {
	msg := env.Message
	if strings.Contains(msg, "STATUS_DLL_INIT_FAILED") {
		switch {
		case cfg.WindowsBlockWin32k:
			msg = "the workload failed to initialize (STATUS_DLL_INIT_FAILED): windowsBlockWin32k forbids the Win32k calls that user32.dll needs; disable it for this program"
		case inServiceSession():
			msg = "the workload failed to initialize (STATUS_DLL_INIT_FAILED): safer-exec is running in session 0 (a service or SSH logon), whose window station a Windows container cannot open, " +
				"so programs that load user32.dll (Node.js, Java, ...) cannot start; run from an interactive session"
		}
	} else if env.ExtendedError != "" {
		msg += " (" + env.ExtendedError + ")"
	}
	return fmt.Errorf("windows sandbox (MXC %s): %s", env.Code, msg)
}

// inServiceSession reports whether the engine runs in session 0, the
// non-interactive session of services and SSH logons.
func inServiceSession() bool {
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
		return false
	}
	return session == 0
}

// emitAudit writes one audit entry in the {"type","target","details"} JSON
// line format the Node runner parses from stderr.
func emitAudit(stderr *mxc.StderrFilter, entryType, target, details string) {
	data, err := json.Marshal(map[string]string{"type": entryType, "target": target, "details": details})
	if err != nil {
		return
	}
	stderr.Emit(append(data, '\n'))
}

// consumeJobEvents turns job notifications into traceExec and resource-limit
// audit entries. Console host processes the OS attaches to the workload are
// plumbing, not workload activity, and are not reported.
func consumeJobEvents(cfg config.ExecConfig, job *winjob.Job, launcherPID uint32, stderr *mxc.StderrFilter, onMemoryLimit func(), workloadStarted *atomic.Bool) {
	conhost := ""
	if root := os.Getenv("SystemRoot"); root != "" {
		conhost = filepath.Join(root, "System32", "conhost.exe")
	}
	traceExec := cfg.TraceExec && cfg.EnableAudit
	for ev := range job.Events() {
		switch ev.Message {
		case winjob.MsgNewProcess:
			if ev.PID == launcherPID {
				continue
			}
			image, ppid, ok := job.Describe(ev.PID)
			if ok && strings.EqualFold(image, conhost) {
				continue
			}
			workloadStarted.Store(true)
			if !traceExec {
				continue
			}
			if !ok {
				// Gone before it could be opened: report it rather than let
				// a short-lived process slip past traceExec.
				emitAudit(stderr, "process-exec", "(exited before it could be identified)", fmt.Sprintf("pid %d", ev.PID))
				continue
			}
			emitAudit(stderr, "process-exec", image, fmt.Sprintf("pid %d started by pid %d", ev.PID, ppid))
		case winjob.MsgActiveProcessLimit:
			if cfg.EnableAudit {
				emitAudit(stderr, "resource-limit", "active-processes", "process creation refused: active process limit reached")
			}
		case winjob.MsgJobMemoryLimit, winjob.MsgProcessMemoryLimit:
			if cfg.EnableAudit {
				emitAudit(stderr, "resource-limit", "memory", fmt.Sprintf("memory limit exceeded by pid %d; workload terminated", ev.PID))
			}
			onMemoryLimit()
		}
	}
}

// maxLibraryLoads bounds the lib-load entries one run reports; a workload
// could otherwise load copies of a DLL under endless names.
const maxLibraryLoads = 10000

// emitLibraryLoads stops the ETW session and reports, as lib-load audit
// entries, each image the workload's process tree loaded. wxc-exec's own
// loads, each process's executable, and the console hosts Windows attaches
// to the workload are left out, as traceExec leaves them out. The events come
// from the kernel through the engine's own session, so the workload cannot
// hide a load; it can only make many of them (and, as with every audit
// entry, print look-alike lines on the stderr it shares with the engine).
func emitLibraryLoads(s *dlltrace.Session, launcherPID uint32, stderr *mxc.StderrFilter) {
	res := s.Stop()
	stderr.EnsureNewline()
	if res.Err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: traceLibraries: %v\n", res.Err)
	}
	if res.StoppedEarly {
		fmt.Fprintln(os.Stderr, "safer-exec: warning: traceLibraries: the ETW session was stopped before the run ended; the library list is incomplete")
	}
	if res.Lost > 0 {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: traceLibraries: %d events were lost; the library list may be incomplete\n", res.Lost)
	}
	mapper := dlltrace.SystemPathMapper()
	conhost := ""
	if root := os.Getenv("SystemRoot"); root != "" {
		conhost = filepath.Join(root, "System32", "conhost.exe")
	}
	skip := func(image string) bool {
		return conhost != "" && strings.EqualFold(mapper.Win32Path(image), conhost)
	}
	loads := dlltrace.Attribute(res.Events, dlltrace.Root{PID: launcherPID, ParentPID: uint32(os.Getpid())}, skip)
	seen := make(map[string]bool, len(loads))
	reported := 0
	for _, l := range loads {
		path := mapper.Win32Path(l.Path)
		if filepath.IsAbs(path) {
			path = longPath(path)
		}
		key := strings.ToLower(path)
		if seen[key] {
			continue
		}
		seen[key] = true
		if reported == maxLibraryLoads {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: traceLibraries: more than %d distinct images were loaded; the rest are not reported\n", maxLibraryLoads)
			break
		}
		process := "unknown process"
		if l.Process != "" {
			process = filepath.Base(mapper.Win32Path(l.Process))
		}
		emitAudit(stderr, "lib-load", path, fmt.Sprintf("loaded by %s (pid %d)", process, l.PID))
		reported++
	}
}

// readCaptureReport loads the denial report MXC wrote into the run directory
// (it stamps a run id into the requested name: denials.<id>.json) and drops
// the start-up denials every container process produces. The capture pointer
// MXC prints on stderr is ignored: the workload can print one too, and
// following it would let the workload pick a file for the engine to read and
// delete. The run directory is denied to every sandbox, so only MXC can have
// written there.
func readCaptureReport(workDir, systemRoot string) *mxc.DenialReport {
	var path string
	matches, _ := filepath.Glob(filepath.Join(workDir, "denials.*.json"))
	sort.Strings(matches)
	for _, m := range matches {
		if strings.HasSuffix(strings.ToLower(m), ".verbose.json") || !strings.EqualFold(filepath.Dir(m), workDir) {
			continue
		}
		if fi, err := os.Lstat(m); err == nil && fi.Mode().IsRegular() {
			path = m
			break
		}
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "safer-exec: warning: MXC produced no denial report for this run")
		return &mxc.DenialReport{}
	}
	report, err := mxc.ReadDenialReport(path)
	// The reports can name sensitive paths; they never outlive the run (the
	// run directory itself is removed when the run ends).
	_ = os.Remove(path)
	_ = os.Remove(mxc.VerboseSibling(path))
	if err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: %v\n", err)
		return &mxc.DenialReport{}
	}
	if report.Summary.DeniedResourcesTruncated {
		fmt.Fprintln(os.Stderr, "safer-exec: warning: the denial report was truncated by MXC's analysis bounds")
	}
	return report.WithoutBaseline(systemRoot)
}

// collectAudit emits the run's denials as audit entries.
func collectAudit(cfg config.ExecConfig, stderr *mxc.StderrFilter, workDir, systemRoot string) {
	if !cfg.EnableAudit {
		return
	}
	report := readCaptureReport(workDir, systemRoot)
	const maxAuditEntries = 1000
	entries := report.AuditEntries()
	if len(entries) > maxAuditEntries {
		entries = entries[:maxAuditEntries]
	}
	stderr.EnsureNewline()
	for _, e := range entries {
		emitAudit(stderr, e.Type, e.Target, e.Detail)
	}
}

// finishLearn builds, merges and emits the learned policy.
func finishLearn(cfg config.ExecConfig, plan *mxc.Plan, workDir string, proxy *egressProxy, protected []string) error {
	in := mxc.LearnInput{
		Cmd:             cfg.Cmd,
		Args:            cfg.Args,
		Report:          readCaptureReport(workDir, plan.SystemRoot),
		Plan:            plan,
		NetworkDisabled: cfg.DisableNetwork,
		Forbidden:       protected,
	}
	if proxy != nil {
		in.ProxyTargets = proxy.connectedTargets()
	}
	policy := mxc.LearnPolicy(in)
	policy = config.OverlayExecConfigToPolicy(cfg, policy)
	if cfg.PolicyFilePath != "" {
		if base, err := config.ReadPolicyFile(cfg.PolicyFilePath); err == nil {
			policy = config.MergePolicies(base, policy)
		}
		if err := config.WritePolicyFile(cfg.PolicyFilePath, policy); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: write merged policy file: %v\n", err)
		}
	}
	data, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("marshaling learned policy: %w", err)
	}
	writeStructured(cfg, "LEARNED:", data)
	return nil
}

// validateRequest asks wxc-exec to parse and validate the request without
// running it.
func validateRequest(cfg config.ExecConfig, launcher, requestPath, request string) error {
	cmd := exec.Command(launcher, "--dry-run", "--config", requestPath)
	cmd.Env = launcherEnv()
	var out, errOut strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	runErr := cmd.Run()
	result := config.ProfileValidationResult{Profile: request, Valid: runErr == nil}
	if runErr != nil {
		msg := strings.TrimSpace(errOut.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		if msg == "" {
			msg = runErr.Error()
		}
		result.Errors = strings.Split(msg, "\n")
	}
	data, _ := json.Marshal(result)
	writeStructured(cfg, "PROFILE:", data)
	if !result.Valid {
		return fmt.Errorf("MXC request validation failed: %s", strings.Join(result.Errors, "; "))
	}
	return nil
}

// windowsFIPSEnabled reads the system FIPS algorithm policy.
func windowsFIPSEnabled() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("Enabled")
	return err == nil && v != 0
}

func handleFIPSWindows(cfg config.ExecConfig) {
	if !cfg.DetectFIPS && !cfg.StrictFIPS {
		return
	}
	enabled := windowsFIPSEnabled()
	if cfg.StrictFIPS && !enabled {
		fmt.Fprintln(os.Stderr, "safer-exec: audit: fips-violation: the Windows FIPS algorithm policy is disabled")
		return
	}
	state := "0"
	if enabled {
		state = "1"
	}
	fmt.Fprintf(os.Stderr, "safer-exec: audit: fips-check: Windows FIPS algorithm policy status: %s\n", state)
}

// lockFileOffset places safer-exec's byte-range locks far beyond any real
// file content. Windows byte-range locks are mandatory for the locked range,
// so locking the data itself would block the sandboxed workload's own reads
// and writes; locking a sentinel byte gives flock-like advisory semantics
// between cooperating safer-exec instances.
const (
	lockFileOffsetHigh = 0x7FFFFFFF
	lockFileOffsetLow  = 0xFFFFFFFE
)

// acquireFileLocks takes the configured shared/exclusive locks, blocking
// until each is available, and holds them for the run.
func acquireFileLocks(specs []config.LockFileSpec) ([]*os.File, error) {
	var files []*os.File
	for _, spec := range specs {
		f, err := os.OpenFile(spec.Path, os.O_RDONLY|os.O_CREATE, 0o644)
		if err != nil {
			releaseFileLocks(files)
			return nil, fmt.Errorf("lock-file %s: %w", spec.Path, err)
		}
		var flags uint32
		if spec.Exclusive {
			flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
		}
		ol := &windows.Overlapped{Offset: lockFileOffsetLow, OffsetHigh: lockFileOffsetHigh}
		if err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, ol); err != nil {
			f.Close()
			releaseFileLocks(files)
			return nil, fmt.Errorf("lock %s: %w", spec.Path, err)
		}
		files = append(files, f)
	}
	return files, nil
}

// releaseFileLocks closes the lock handles, which releases their locks.
func releaseFileLocks(files []*os.File) {
	for _, f := range files {
		f.Close()
	}
}

// runInit is not used on Windows (the re-exec pattern is Linux-specific).
func runInit(cfg config.ExecConfig) error {
	return run(cfg)
}

// runInitReduced is not used on Windows.
func runInitReduced(cfg config.ExecConfig) error {
	return run(cfg)
}

// runDiagnostics reports Windows and MXC capabilities.
func runDiagnostics() config.DiagnosticsResult {
	result := config.DiagnosticsResult{
		Platform:     "windows",
		Arch:         runtime.GOARCH,
		Capabilities: make(map[string]config.CapabilityInfo),
		Features:     make(map[string]bool),
	}
	v := windows.RtlGetVersion()
	result.Kernel = fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
	result.Release = windowsRelease(v.BuildNumber)

	launcher, err := resolveLauncher()
	if err != nil {
		result.Capabilities["mxc_executor"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
	} else {
		result.Capabilities["mxc_executor"] = config.CapabilityInfo{Available: true, Detail: launcher}
	}

	var probe *mxc.ProbeResult
	if err == nil {
		probe, err = probeHost(launcher)
		if err != nil {
			result.Capabilities["mxc_probe"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
		} else {
			detail := "tier " + probe.Tier
			if len(probe.Warnings) > 0 {
				detail += "; " + strings.Join(probe.Warnings, "; ")
			}
			result.Capabilities["mxc_probe"] = config.CapabilityInfo{Available: true, Detail: detail}
		}
	}
	flag := func(name, capability, detail string) bool {
		ok := probe.Flag(name)
		result.Capabilities[capability] = config.CapabilityInfo{Available: ok, Detail: detail}
		return ok
	}
	base := flag("baseContainerApiPresent", "base_container", "CreateProcessSecurityEnvironment (OS-enforced filesystem grants, WFP egress, per-container proxy)")
	nativeCapture := flag("nativeCaptureAvailable", "native_denial_capture", "learning-mode trace for audit, learn and dry-run")
	guardedCapture := flag("guardedCaptureAvailable", "guarded_denial_capture", "elevated WPR fallback for denial capture")
	denyPaths := flag("baseContainerSupportsDenyPaths", "denied_paths", "native deny grants (persistence-location denies)")
	proxyOK := flag("baseContainerSupportsIdentitylessLoopbackProxy", "loopback_proxy", "container egress confined to the safer-exec egress proxy")
	loopback := flag("baseContainerSupportsIngressHostLoopbackAllow", "host_loopback", "host loopback access for direct-egress policies")
	flag("baseContainerSupportsEnumeratePaths", "enumerate_paths", "metadata-only access to directories outside the grants (PSEC 1.1); without it, tools that resolve real paths through ungranted ancestors fail")
	interactive := !inServiceSession()
	result.Capabilities["interactive_session"] = config.CapabilityInfo{Available: interactive, Detail: "programs that load user32.dll (Node.js, Java) cannot start in a container launched from session 0 (services, SSH)"}

	tierOK := probe != nil && (probe.Tier == mxc.TierBaseContainer || probe.Tier == mxc.TierAppContainerBfs)
	mutates := probe.MutatesHost()
	result.Capabilities["host_acl_mutation_required"] = config.CapabilityInfo{Available: mutates, Detail: "the selected tier changes host file ACLs (requires windowsAllowDaclMutation)"}

	job, jerr := winjob.New(winjob.Limits{})
	if jerr == nil {
		job.Close()
		result.Capabilities["job_objects"] = config.CapabilityInfo{Available: true, Detail: "nested job objects for memory, CPU and process limits"}
	} else {
		result.Capabilities["job_objects"] = config.CapabilityInfo{Available: false, Detail: jerr.Error()}
	}
	jobs := jerr == nil
	libErr := dlltrace.Probe()
	if libErr == nil {
		result.Capabilities["library_tracing"] = config.CapabilityInfo{Available: true, Detail: "ETW image-load events (Microsoft-Windows-Kernel-Process) for traceLibraries"}
	} else {
		result.Capabilities["library_tracing"] = config.CapabilityInfo{Available: false, Detail: "traceLibraries: " + libErr.Error()}
	}
	fips := windowsFIPSEnabled()
	result.Capabilities["fips_detection"] = config.CapabilityInfo{Available: true, Detail: fmt.Sprintf("FipsAlgorithmPolicy Enabled=%t", fips)}

	sandbox := tierOK || (probe != nil && mutates)
	capture := nativeCapture || guardedCapture
	result.Features["mxc_process_container"] = sandbox
	result.Features["base_container"] = base
	result.Features["network_isolation"] = sandbox
	result.Features["ip_pinned_egress"] = sandbox && base
	result.Features["egress_proxy"] = proxyOK
	result.Features["host_loopback"] = loopback
	result.Features["file_read_restriction"] = sandbox
	result.Features["file_write_restriction"] = sandbox
	result.Features["denied_paths"] = denyPaths
	result.Features["memory_limit"] = jobs
	result.Features["cpu_limit"] = jobs
	result.Features["process_limit"] = jobs
	result.Features["fork_control"] = jobs
	result.Features["exec_control"] = false
	result.Features["io_limit"] = false
	result.Features["audit_tracing"] = capture
	result.Features["learning_mode"] = capture
	result.Features["dry_run"] = capture
	result.Features["trace_exec"] = jobs
	result.Features["filesystem_diff"] = true
	result.Features["strict_mode"] = true
	result.Features["fips_detection"] = true
	result.Features["ui_restriction"] = sandbox
	result.Features["gui_runtime_support"] = sandbox && interactive
	result.Features["profile_validation"] = launcher != ""
	result.Features["trace_libraries"] = libErr == nil
	result.Features["trace_http_urls"] = false
	result.Features["allow_url_rules"] = false
	result.Features["trace_crypto"] = false
	result.Features["crypto_control"] = false
	result.Features["gpu_control"] = false
	result.Features["tpm_control"] = false
	result.Features["antivm_spoofing"] = false
	result.Features["landlock_filesystem"] = false
	result.Features["landlock_layers"] = false
	result.Features["apparmor_safer_exec"] = false
	result.Features["proc_hidepid"] = false
	result.Features["time_isolation"] = false
	result.Features["ipc_isolation"] = sandbox
	return result
}

// windowsRelease describes the OS from the registry's product data.
func windowsRelease(build uint32) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return fmt.Sprintf("Windows build %d", build)
	}
	defer k.Close()
	display, _, _ := k.GetStringValue("DisplayVersion")
	ubr, _, _ := k.GetIntegerValue("UBR")
	name := "Windows 10"
	if build >= 22000 {
		name = "Windows 11"
	}
	// Server editions share client build numbers; MXC supports only
	// Windows 11 client builds.
	if kind, _, _ := k.GetStringValue("InstallationType"); strings.EqualFold(kind, "Server") || strings.EqualFold(kind, "Server Core") {
		if product, _, _ := k.GetStringValue("ProductName"); product != "" {
			name = product
		} else {
			name = "Windows Server"
		}
	}
	if display != "" {
		return fmt.Sprintf("%s %s (build %d.%d)", name, display, build, ubr)
	}
	return fmt.Sprintf("%s (build %d.%d)", name, build, ubr)
}
