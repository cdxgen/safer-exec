//go:build linux

package main

import (
	"bytes"
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
	"unsafe"

	"github.com/cdxgen/safer-exec/go/internal/config"
	"github.com/cdxgen/safer-exec/go/internal/fsdiff"
	"github.com/cdxgen/safer-exec/go/internal/httptrace"
	"github.com/cdxgen/safer-exec/go/internal/learner"
)

const cgroupV2Root = "/sys/fs/cgroup"

const (
	sysKCMP        = sysKCMP_unified
	sysSYSCALL     = sysSYSCALL_unified
	sysFORK        = sysFORK_unified
	sysVFORK       = sysVFORK_unified
	sysEXECVEAT    = sysEXECVEAT_unified
	sysCLONE3      = sysCLONE3_unified
	sysBPF         = sysBPF_unified
	sysUSERFAULTFD = sysUSERFAULTFD_unified
	sysIOPERM      = sysIOPERM_unified
	sysIOPL        = sysIOPL_unified
)

const (
	seccompRetKill  = 0x00000000
	seccompRetTrap  = 0x00030000
	seccompRetErrno = 0x00050000
	seccompRetAllow = 0x7fff0000
)

const sysSeccomp = sysSeccomp_unified

const (
	bpfLoadWordAbsolute = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJmpEq            = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfJmpSet           = 0x45 // BPF_JMP | BPF_JSET | BPF_K
	bpfJmpReturn        = 0x06 // BPF_RET | BPF_K
	bpfAluAnd           = 0x54 // BPF_ALU | BPF_AND | BPF_K
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

// isUnshareFlagSupported checks whether the system's unshare binary supports
// the given flag (e.g., "-t" for time namespace, "-i" for IPC namespace).
// Returns true if `unshare <flag> /bin/true` succeeds.
func isUnshareFlagSupported(flag string) bool {
	cmd := exec.Command("unshare", flag, "/bin/true")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
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

	// Start eBPF HTTP URL tracer BEFORE the user namespace check so it works
	// in both full and reduced isolation mode. Loading BPF takes ~10-50ms.
	var httpTracer httptrace.Tracer
	var httpEvents []config.HTTPAccessEntry
	var stopPIDRefresh chan struct{}
	var cryptoResult *config.CryptoResult

	// Auto-enable HTTP URL tracing if crypto tracing is requested
	if cfg.TraceCrypto && !cfg.TraceHTTPURLs {
		cfg.TraceHTTPURLs = true
	}

	if cfg.TraceHTTPURLs {
		if tr, err2 := httptrace.New(); err2 == nil {
			httpTracer = tr

			// Enable crypto tracing if requested
			if cfg.TraceCrypto {
				if err3 := httpTracer.EnableCryptoTracing(); err3 != nil {
					fmt.Fprintf(os.Stderr, "safer-exec: warning: crypto-trace: %v\n", err3)
				} else {
					// Cipher probes run against all PIDs so they fire before we
					// know the child PID; bypass the per-PID filter here.
					_ = httpTracer.SetTraceAll(true)
				}
			}

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

			// Collect all candidate binary paths and deduplicate before
			// attaching uprobes, to avoid attaching the same probe twice.
			probeTargets := make(map[string]bool)
			if cmdPath != "" {
				probeTargets[cmdPath] = true

				// Resolve shebang if the command is a script
				if data, err := os.ReadFile(cmdPath); err == nil && len(data) > 2 && data[0] == '#' && data[1] == '!' {
					shebang := string(data[:bytes.IndexByte(data, '\n')])
					parts := strings.Fields(shebang[2:])
					if len(parts) > 0 {
						interp := parts[0]
						if strings.HasSuffix(interp, "/env") && len(parts) > 1 {
							interp = parts[1]
						}
						if interpPath, err := exec.LookPath(interp); err == nil {
							probeTargets[interpPath] = true
						}
					}
				}
				// Add well-known interpreter paths for package managers
				switch filepath.Base(cmdPath) {
				case "npm", "npx", "yarn", "pnpm", "corepack":
					if nodePath, err := exec.LookPath("node"); err == nil {
						probeTargets[nodePath] = true
					}
				case "bun":
					if bunPath, err := exec.LookPath("bun"); err == nil {
						probeTargets[bunPath] = true
					}
				case "deno":
					if denoPath, err := exec.LookPath("deno"); err == nil {
						probeTargets[denoPath] = true
					}
				case "pip", "pip3", "pipenv", "poetry", "uv":
					if pythonPath, err := exec.LookPath("python3"); err == nil {
						probeTargets[pythonPath] = true
					}
				}
			}
			for p := range probeTargets {
				_ = httpTracer.AttachStaticOpenSSL(p)
				_ = httpTracer.AttachGoTLS(p)
			}
		} else {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: http-trace: %v\n", err2)
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
			if httpTracer != nil {
				httpTracer.Close()
			}
			return fmt.Errorf("user namespaces unavailable")
		}
		fmt.Fprintf(os.Stderr, "safer-exec: warning: user namespaces unavailable — running with reduced isolation (seccomp + landlock only; no filesystem, PID, or network namespace isolation). Install the safer-exec AppArmor profile for full isolation. See README for details.\n")
		return runReduced(cfg, cfgJSON, selfPath, httpTracer, &httpEvents, &stopPIDRefresh)
	}

	// Use system unshare to create namespaces before Go starts
	unshareArgs := []string{"-U", "-m", "-p", "--fork", "-u", "-r"}
	if isUnshareFlagSupported("-t") {
		unshareArgs = append(unshareArgs, "-t")
	}
	if isUnshareFlagSupported("-i") {
		unshareArgs = append(unshareArgs, "-i")
	}
	if cfg.DisableNetwork {
		unshareArgs = append(unshareArgs, "-n")
	}
	unshareArgs = append(unshareArgs, "--", selfPath, "--init")

	// Write config to a temp file to avoid exposing secrets in /proc/self/environ.
	// Falls back to env var if temp file cannot be created.
	configPath, err := writeConfigToTempFile(cfgJSON)
	var envVar string
	if err == nil {
		defer os.Remove(configPath)
		envVar = fmt.Sprintf("SAFER_EXEC_CONFIG_PATH=%s", configPath)
	} else {
		envVar = fmt.Sprintf("SAFER_EXEC_CONFIG=%s", string(cfgJSON))
	}
	cmd := exec.Command("unshare", unshareArgs...)
	cmd.Env = append(config.FilteredEnviron(), envVar)
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

	var httpEventsDone chan struct{}
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

		httpEventsDone = make(chan struct{})
		go func() {
			defer close(httpEventsDone)
			for ev := range httpTracer.Events() {
				entry := config.HTTPAccessEntry{
					Method:               ev.Method,
					Host:                 ev.Host,
					Path:                 ev.Path,
					Protocol:             ev.Protocol,
					Port:                 ev.Port,
					Query:                ev.Query,
					Body:                 ev.Body,
					Source:               ev.Source.String(),
					PID:                  ev.PID,
					Cipher:               ev.CipherName,
					CipherIANAName:       httptrace.IANACipherName(ev.CipherName),
					CipherIANAID:         ev.CipherSuite,
					TLSVersion:           ev.TLSVersion,
					CipherBits:           ev.CipherBits,
					CryptoLibrary:        ev.CryptoLibrary,
					CryptoLibraryVersion: ev.CryptoLibraryVersion,
				}
				if cfg.EnableAudit {
					logAuditHTTPEntry(entry)
				}
				httpEvents = append(httpEvents, entry)
			}
		}()
	}

	// closeHTTPTracer shuts down HTTP tracing and waits for the event goroutine
	// to finish draining and writing all audit entries before returning.
	// Must be called instead of httpTracer.Close() everywhere in this function.
	closeHTTPTracer := func() {
		if httpTracer == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
		httpTracer.Close()
		if httpEventsDone != nil {
			<-httpEventsDone
		}
	}

	err = cmd.Wait()
	if stopPIDRefresh != nil {
		close(stopPIDRefresh)
	}
	if stopMonitor != nil {
		close(stopMonitor)
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if cfg.EnableAudit && auditR != nil {
				collectAuditLog(auditR)
			}
			code := exitErr.ExitCode()
			if code == 126 || code == 127 {
				// unshare failed to execute the binary (126) or command not found (127).
				// This can happen on systems where user+mount namespaces block exec
				// (e.g. OrbStack VMs, certain container runtimes). Fall back to
				// reduced isolation mode instead of failing.
				fmt.Fprintf(os.Stderr, "safer-exec: warning: unshare namespace exec failed (exit %d) — falling back to reduced isolation mode\n", code)
				// Clean up the audit pipe created for this attempt; runReduced creates its own.
				if auditR != nil {
					auditR.Close()
				}
				// Do NOT close httpTracer here — pass it to runReduced so HTTP tracing
				// continues working in reduced isolation mode.
				return runReduced(cfg, cfgJSON, selfPath, httpTracer, &httpEvents, &stopPIDRefresh)
			}
			if code == 132 || code == 137 || code == 153 {
				closeHTTPTracer()
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
			closeHTTPTracer()
			if code == -1 {
				fmt.Fprintf(os.Stderr, "safer-exec: process killed by signal: %v\n", exitErr.ProcessState.String())
			}
			return &ExitError{Code: code}
		}
		closeHTTPTracer()
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

	closeHTTPTracer()

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

	// Build and emit crypto result if tracing was enabled
	if cfg.TraceCrypto && httpTracer != nil {
		cryptoResult = buildCryptoResult(httpTracer, httpEvents)
		if len(cfg.AllowCiphers) > 0 && len(cryptoResult.Ciphers) > 0 {
			allowedMap := make(map[string]bool)
			for _, ac := range cfg.AllowCiphers {
				allowedMap[ac] = true
			}
			for i := range cryptoResult.Ciphers {
				c := &cryptoResult.Ciphers[i]
				if !allowedMap[c.Name] && !allowedMap[c.IANAName] {
					logAuditEntry("cipher-violation", c.Name)
					fmt.Fprintf(os.Stderr, "safer-exec: cipher-violation: cipher %s (IANA: %s) is not allowed by policy\n", c.Name, c.IANAName)
				}
			}
		}
		if cfg.EnableAudit {
			logAuditCryptoResult(cfg, cryptoResult)
		}
		if data, err := json.Marshal(cryptoResult); err == nil {
			writeStructured(cfg, "CRYPTO:", data)
		}
		if cfg.CBOMOutputPath != "" {
			writeCBOMFile(cfg.CBOMOutputPath, cryptoResult)
		}
	}

	return nil
}

// buildCryptoResult aggregates detected libraries, cipher suites, and operations
// from the tracer and HTTP events into a CryptoResult.
func buildCryptoResult(tracer httptrace.Tracer, httpEvents []config.HTTPAccessEntry) *config.CryptoResult {
	result := &config.CryptoResult{Platform: "linux"}

	// Collect libraries from tracer
	for _, lib := range tracer.DetectedLibraries() {
		result.Libraries = append(result.Libraries, config.CryptoLibrary{
			Name:    lib.Name,
			Version: lib.Version,
			Path:    lib.Path,
			Source:  lib.Source,
		})
	}

	// Retroactively populate missing cipher info on HTTP events
	if cl, ok := tracer.(interface {
		CipherForConnID(uint64, uint32) (httptrace.CipherResult, bool)
	}); ok {
		for i := range httpEvents {
			e := &httpEvents[i]
			if e.Cipher == "" {
				if cr, found := cl.CipherForConnID(0, e.PID); found {
					e.Cipher = cr.Name
					e.CipherIANAName = cr.IANAName
					e.CipherIANAID = cr.IANAID
					e.TLSVersion = cr.Protocol
					e.CipherBits = cr.Bits
				}
			}
		}
	}

	// Deduplicate ciphers and collect operations
	seenCiphers := make(map[string]bool)
	seenOps := make(map[string]*config.CryptoOperation)

	for _, e := range httpEvents {
		if e.Cipher == "" {
			continue
		}
		// Check for crypto operation entries
		if e.Cipher == "MD5" || e.Cipher == "SHA-1" || e.Cipher == "SHA-256" || e.Cipher == "SHA-512" || e.Cipher == "AES" || e.Cipher == "SHA-224" || e.Cipher == "SHA-384" {
			opType := "digest"
			if e.Cipher == "AES" {
				if e.CipherBits == 6 {
					opType = "decrypt"
				} else {
					opType = "encrypt"
				}
			}
			key := opType + ":" + e.Cipher
			if op, exists := seenOps[key]; exists {
				op.Count++
			} else {
				seenOps[key] = &config.CryptoOperation{
					Type:      opType,
					Algorithm: e.Cipher,
					Library:   "OpenSSL/Go internal",
					PID:       e.PID,
					Count:     1,
				}
			}
			continue
		}

		key := e.Cipher + ":" + e.CryptoLibrary
		if seenCiphers[key] {
			continue
		}
		seenCiphers[key] = true

		dec := httptrace.DecomposeCipherName(e.Cipher)
		result.Ciphers = append(result.Ciphers, config.CipherInfo{
			Name:           e.Cipher,
			IANAName:       e.CipherIANAName,
			IANAID:         e.CipherIANAID,
			Protocol:       e.TLSVersion,
			Bits:           e.CipherBits,
			KeyExchange:    dec.KeyExchange,
			Authentication: dec.Authentication,
			Encryption:     dec.Encryption,
			EncryptionBits: dec.EncryptionBits,
			Hash:           dec.Hash,
			Mode:           dec.Mode,
			Library:        e.CryptoLibrary,
			LibraryVersion: e.CryptoLibraryVersion,
			PID:            e.PID,
		})
	}

	for _, op := range seenOps {
		result.Operations = append(result.Operations, *op)
	}

	if result.Libraries == nil {
		result.Libraries = []config.CryptoLibrary{}
	}
	if result.Ciphers == nil {
		result.Ciphers = []config.CipherInfo{}
	}
	if result.Operations == nil {
		result.Operations = []config.CryptoOperation{}
	}

	return result
}

// cbomDoc is a minimal CycloneDX CBOM document structure.
type cbomDoc struct {
	BomFormat   string          `json:"bomFormat"`
	SpecVersion string          `json:"specVersion"`
	Version     int             `json:"version"`
	Components  []cbomComponent `json:"components,omitempty"`
}

type cbomComponent struct {
	Type             string           `json:"type"`
	Name             string           `json:"name"`
	Version          string           `json:"version,omitempty"`
	CryptoProperties *cbomCryptoProps `json:"cryptoProperties,omitempty"`
}

type cbomCryptoProps struct {
	AssetType                  string            `json:"assetType"`
	AlgorithmProperties        *cbomAlgoProps    `json:"algorithmProperties,omitempty"`
	RelatedCryptoMaterialProps *cbomRelatedProps `json:"relatedCryptoMaterialProperties,omitempty"`
}

type cbomAlgoProps struct {
	Primitive              string   `json:"primitive,omitempty"`
	ParameterSetIdentifier string   `json:"parameterSetIdentifier,omitempty"`
	Mode                   string   `json:"mode,omitempty"`
	ExecutionEnvironment   string   `json:"executionEnvironment,omitempty"`
	ImplementationPlatform string   `json:"implementationPlatform,omitempty"`
	CryptoFunctions        []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel int      `json:"classicalSecurityLevel,omitempty"`
}

type cbomRelatedProps struct {
	Type string `json:"type"`
}

// writeCBOMFile writes a minimal CycloneDX CBOM JSON document to the given path.
func writeCBOMFile(path string, cryptoResult *config.CryptoResult) {
	doc := cbomDoc{
		BomFormat:   "CycloneDX",
		SpecVersion: "1.7",
		Version:     1,
	}

	for _, lib := range cryptoResult.Libraries {
		ver := lib.Version
		if ver == "" {
			ver = "unknown"
		}
		doc.Components = append(doc.Components, cbomComponent{
			Type:    "cryptographic-asset",
			Name:    lib.Name,
			Version: ver,
			CryptoProperties: &cbomCryptoProps{
				AssetType: "related-crypto-material",
				RelatedCryptoMaterialProps: &cbomRelatedProps{
					Type: "library",
				},
			},
		})
	}

	for _, c := range cryptoResult.Ciphers {
		funcs := []string{"encrypt"}
		if c.Mode != "" {
			funcs = append(funcs, "decrypt")
		}
		doc.Components = append(doc.Components, cbomComponent{
			Type:    "cryptographic-asset",
			Name:    c.Name,
			Version: c.Protocol,
			CryptoProperties: &cbomCryptoProps{
				AssetType: "algorithm",
				AlgorithmProperties: &cbomAlgoProps{
					Primitive:              algoPrimitive(c),
					ParameterSetIdentifier: c.Hash,
					Mode:                   c.Mode,
					ExecutionEnvironment:   c.Library,
					ImplementationPlatform: c.Library,
					CryptoFunctions:        funcs,
					ClassicalSecurityLevel: c.Bits,
				},
			},
		})
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: cbom marshal: %v\n", err)
		return
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: cbom write: %v\n", err)
	}
}

func algoPrimitive(c config.CipherInfo) string {
	switch {
	case c.Mode == "GCM" || c.Mode == "CCM" || c.Mode == "POLY1305":
		return "aead"
	case c.Encryption != "":
		return "block-cipher"
	case c.KeyExchange != "":
		return "key-agree"
	default:
		return "other"
	}
}

// runLearn executes the command in learning mode using strace to observe behavior.
func runLearn(cfg config.ExecConfig) error {
	l := learner.New()

	// Auto-enable HTTP URL tracing if crypto tracing is requested
	if cfg.TraceCrypto && !cfg.TraceHTTPURLs {
		cfg.TraceHTTPURLs = true
	}

	// Set up eBPF HTTP tracer if requested
	var httpTracer httptrace.Tracer
	var httpEntries []config.HTTPAccessEntry
	if cfg.TraceHTTPURLs {
		if tr, err := httptrace.New(); err == nil {
			httpTracer = tr

			// Enable crypto tracing if requested
			if cfg.TraceCrypto {
				if err2 := httpTracer.EnableCryptoTracing(); err2 != nil {
					fmt.Fprintf(os.Stderr, "safer-exec: warning: crypto-trace: %v\n", err2)
				}
			}

			// In learn mode with strace, we set trace-all because we don't
			// know child PIDs ahead of time; strace spawns them itself.
			_ = tr.SetTraceAll(true)
			go func() {
				for ev := range tr.Events() {
					httpEntries = append(httpEntries, config.HTTPAccessEntry{
						Method:               ev.Method,
						Host:                 ev.Host,
						Path:                 ev.Path,
						Source:               ev.Source.String(),
						PID:                  ev.PID,
						Cipher:               ev.CipherName,
						CipherIANAName:       httptrace.IANACipherName(ev.CipherName),
						CipherIANAID:         ev.CipherSuite,
						TLSVersion:           ev.TLSVersion,
						CipherBits:           ev.CipherBits,
						CryptoLibrary:        ev.CryptoLibrary,
						CryptoLibraryVersion: ev.CryptoLibraryVersion,
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

	// Build and emit crypto result if tracing was enabled
	if cfg.TraceCrypto && httpTracer != nil {
		cryptoResult := buildCryptoResult(httpTracer, httpEntries)
		policy.CryptoCiphers = cryptoResult.Ciphers
		policy.CryptoLibraries = cryptoResult.Libraries
		policy.CryptoOperations = cryptoResult.Operations
		if cfg.EnableAudit {
			logAuditCryptoResult(cfg, cryptoResult)
		}
		if data, err := json.Marshal(cryptoResult); err == nil {
			writeStructured(cfg, "CRYPTO:", data)
		}
		if cfg.CBOMOutputPath != "" {
			writeCBOMFile(cfg.CBOMOutputPath, cryptoResult)
		}
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
func runReduced(cfg config.ExecConfig, cfgJSON []byte, selfPath string, httpTracer httptrace.Tracer, httpEvents *[]config.HTTPAccessEntry, stopPIDRefresh *chan struct{}) error {
	// Filesystem diffing requires OverlayFS (mount namespace). Skip and warn.
	if cfg.EnableDiff {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: --diff requires mount namespace isolation; skipped in reduced isolation mode\n")
	}

	var auditR, auditW *os.File
	if cfg.EnableAudit {
		var err error
		auditR, auditW, err = os.Pipe()
		if err != nil {
			if httpTracer != nil {
				httpTracer.Close()
			}
			return fmt.Errorf("creating audit pipe: %w", err)
		}
	}

	// Write config to a temp file to avoid exposing secrets in /proc/self/environ.
	// Falls back to env var if temp file cannot be created.
	configPath, err := writeConfigToTempFile(cfgJSON)
	var envVar string
	if err == nil {
		defer os.Remove(configPath)
		envVar = fmt.Sprintf("SAFER_EXEC_CONFIG_PATH=%s", configPath)
	} else {
		envVar = fmt.Sprintf("SAFER_EXEC_CONFIG=%s", string(cfgJSON))
	}
	cmd := exec.Command(selfPath, "--init-reduced")
	cmd.Env = append(config.FilteredEnviron(), envVar)
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
		if httpTracer != nil {
			httpTracer.Close()
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

	// Start eBPF PID refresh and event capture goroutines (reduced mode).
	// SetTraceAll is used here because in reduced mode there is no PID namespace
	// isolation, and the PID filter may not correctly resolve child PIDs on some
	// kernels (e.g. OrbStack, custom VMM kernels).
	var httpEventsDone chan struct{}
	if httpTracer != nil {
		rootPID := uint32(cmd.Process.Pid)
		_ = httpTracer.AddPID(rootPID)
		_ = httpTracer.SetTraceAll(true)
		*stopPIDRefresh = make(chan struct{})
		go func() {
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				for p := range httptrace.PidDescendants(rootPID) {
					_ = httpTracer.AddPID(p)
				}
				select {
				case <-*stopPIDRefresh:
					return
				case <-ticker.C:
				}
			}
		}()

		httpEventsDone = make(chan struct{})
		go func() {
			defer close(httpEventsDone)
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
				*httpEvents = append(*httpEvents, entry)
			}
		}()
	}

	waitErr := cmd.Wait()
	if stopPIDRefresh != nil && *stopPIDRefresh != nil {
		close(*stopPIDRefresh)
	}
	if stopMonitor != nil {
		close(stopMonitor)
	}
	if httpTracer != nil {
		time.Sleep(100 * time.Millisecond)
		httpTracer.Close()
		if httpEventsDone != nil {
			<-httpEventsDone
		}
	}

	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
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
		return fmt.Errorf("reduced sandbox: %w", waitErr)
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

	if err := applyLandlockFilesystem(cfg); err != nil {
		if cfg.Strict {
			return fmt.Errorf("landlock filesystem: %w", err)
		}
		fmt.Fprintf(os.Stderr, "safer-exec: warning: landlock filesystem: %v\n", err)
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
	// Clear audit FD env var to prevent child processes from discovering it
	os.Unsetenv("SAFER_EXEC_AUDIT_FD")

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

	if err := applyLandlockFilesystem(cfg); err != nil {
		if cfg.Strict {
			return fmt.Errorf("landlock filesystem: %w", err)
		}
		fmt.Fprintf(os.Stderr, "safer-exec: warning: landlock filesystem: %v\n", err)
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
	if cfg.MaxCPUCores == 0 && cfg.MaxMemoryMB == 0 && cfg.MaxProcesses == 0 &&
		cfg.MaxReadIOPS == 0 && cfg.MaxWriteIOPS == 0 && cfg.MaxReadBps == 0 && cfg.MaxWriteBps == 0 {
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
	if cfg.MaxReadIOPS > 0 || cfg.MaxWriteIOPS > 0 || cfg.MaxReadBps > 0 || cfg.MaxWriteBps > 0 {
		rio := cfg.MaxReadIOPS
		wio := cfg.MaxWriteIOPS
		rbps := cfg.MaxReadBps
		wbps := cfg.MaxWriteBps
		if rio == 0 {
			rio = -1
		}
		if wio == 0 {
			wio = -1
		}
		if rbps == 0 {
			rbps = -1
		}
		if wbps == 0 {
			wbps = -1
		}
		ioMax := fmt.Sprintf("%d:%d rbps=%d wbps=%d riops=%d wiops=%d\n", 8, 0, rbps, wbps, rio, wio)
		if err := os.WriteFile(filepath.Join(cgroupPath, "io.max"), []byte(ioMax), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: failed to set io.max: %v\n", err)
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

	if err := syscall.Mount("tmpfs", newRoot, "tmpfs", syscall.MS_NODEV|syscall.MS_NOEXEC|syscall.MS_NOSUID, "size=64m"); err != nil {
		return fmt.Errorf("mount tmpfs: %w", err)
	}

	if err := os.MkdirAll(filepath.Join(newRoot, "tmp"), 0o777); err != nil {
		return fmt.Errorf("mkdir tmp: %w", err)
	}

	for _, path := range cfg.ReadPaths {
		if path == "/" {
			continue
		}
		if path == "/" {
			continue
		}
		target := filepath.Join(newRoot, path)
		fi, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "safer-exec: warning: cannot resolve symlink read path %s: %v\n", path, err)
				continue
			}
			if !isPathAllowed(resolved, cfg.ReadPaths, cfg.WritePaths) {
				fmt.Fprintf(os.Stderr, "safer-exec: warning: symlink read path %s resolves to %s which is outside allowed paths, skipping\n", path, resolved)
				continue
			}
			fi, err = os.Stat(resolved)
			if err != nil {
				continue
			}
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
	for _, path := range cfg.WritePaths {
		if path == "/" {
			continue
		}
		target := filepath.Join(newRoot, path)
		fi, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "safer-exec: warning: cannot resolve symlink write path %s: %v\n", path, err)
				continue
			}
			if !isPathAllowed(resolved, cfg.ReadPaths, cfg.WritePaths) {
				fmt.Fprintf(os.Stderr, "safer-exec: warning: symlink write path %s resolves to %s which is outside allowed paths, skipping\n", path, resolved)
				continue
			}
			fi, err = os.Stat(resolved)
			if err != nil {
				continue
			}
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

		if err := syscall.Mount(path, target, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
			if cfg.Strict {
				return fmt.Errorf("bind mount %s: %w", path, err)
			}
			fmt.Fprintf(os.Stderr, "safer-exec: warning: bind mount %s: %v\n", path, err)
			continue
		}
	}
	return finalizeFilesystem(newRoot, cfg)
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
	return finalizeFilesystem(newRoot, cfg)
}

func finalizeFilesystem(newRoot string, cfg config.ExecConfig) error {
	putRoot := filepath.Join(newRoot, ".put")
	_ = os.Mkdir(putRoot, 0o755)

	if err := syscall.PivotRoot(newRoot, putRoot); err != nil {
		if cfg.Strict {
			return fmt.Errorf("pivot_root failed: %w", err)
		}
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

	// Mount a fresh proc filesystem with hidepid=2 to prevent
	// leaking host process information through /proc.
	// subset=pid restricts the view to PID-related entries only.
	if _, err := os.Stat("/proc"); err == nil {
		_ = syscall.Unmount("/proc", syscall.MNT_DETACH)
	}
	_ = os.MkdirAll("/proc", 0o555)
	if err := syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, "hidepid=2,subset=pid"); err != nil {
		// Fall back to standard proc mount without options on older kernels
		_ = syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, "")
	}
	return nil
}

type landlockRulesetAttr struct{ HandledAccessFS, HandledAccessNet uint64 }
type landlockNetPortAttr struct{ AllowedAccess, Port uint64 }
type landlockPathBeneathAttr struct {
	AllowedAccess uint64
	ParentFd      int32
}

const (
	landlockCreateRulesetVersion = 1 << 0
	landlockAccessNetBindTCP     = 1 << 0
	landlockAccessNetConnectTCP  = 1 << 1
	landlockRuleNetPort          = 2
	landlockRulePathBeneath      = 1
)

// Landlock filesystem access rights (ABI v3+).
const (
	landlockAccessFSExecute    = 1 << 0
	landlockAccessFSWriteFile  = 1 << 1
	landlockAccessFSReadFile   = 1 << 2
	landlockAccessFSReadDir    = 1 << 3
	landlockAccessFSRemoveDir  = 1 << 4
	landlockAccessFSRemoveFile = 1 << 5
	landlockAccessFSMakeChar   = 1 << 6
	landlockAccessFSMakeDir    = 1 << 7
	landlockAccessFSMakeReg    = 1 << 8
	landlockAccessFSMakeSock   = 1 << 9
	landlockAccessFSMakeFIFO   = 1 << 10
	landlockAccessFSMakeBlock  = 1 << 11
	landlockAccessFSMakeSym    = 1 << 12
	landlockAccessFSRefer      = 1 << 13
	landlockAccessFSTruncate   = 1 << 14
)

func getBindPortsAndWildcard(allowListen []string) ([]int, bool) {
	var ports []int
	hasWildcard := false
	for _, item := range allowListen {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if item == "*" || !strings.Contains(item, ":") {
			var p int
			if _, err := fmt.Sscanf(item, "%d", &p); err == nil && p > 0 && p <= 65535 {
				ports = append(ports, p)
			} else {
				hasWildcard = true
			}
		} else {
			var portStr string
			if strings.Contains(item, "]") {
				parts := strings.Split(item, "]:")
				if len(parts) == 2 {
					portStr = parts[1]
				}
			} else {
				parts := strings.Split(item, ":")
				portStr = parts[len(parts)-1]
			}
			if portStr == "*" {
				hasWildcard = true
			} else {
				var p int
				if _, err := fmt.Sscanf(portStr, "%d", &p); err == nil && p > 0 && p <= 65535 {
					ports = append(ports, p)
				}
			}
		}
	}
	return ports, hasWildcard
}

func applyLandlockNetwork(cfg config.ExecConfig) error {
	// Prevent unit tests from accidentally poisoning the Go test runner.
	if os.Getenv("SAFER_EXEC_CONFIG_PATH") == "" && os.Getenv("SAFER_EXEC_CONFIG") == "" && strings.HasSuffix(os.Args[0], ".test") {
		return nil
	}

	var handledAccess uint64 = 0

	bindPorts, bindWildcard := getBindPortsAndWildcard(cfg.AllowListen)
	restrictBind := !bindWildcard
	if restrictBind {
		handledAccess |= landlockAccessNetBindTCP
	}

	restrictConnect := len(cfg.AllowIPs) > 0 || len(cfg.AllowPorts) > 0 || len(cfg.AllowURLRules) > 0 || cfg.DisableNetwork
	if restrictConnect {
		handledAccess |= landlockAccessNetConnectTCP
	}

	if handledAccess == 0 {
		return nil
	}

	abi, _, errno := syscall.RawSyscall(sysLandlockCreateRuleset, 0, 0, landlockCreateRulesetVersion)
	if errno != 0 || abi < 4 {
		return nil
	}

	attr := landlockRulesetAttr{HandledAccessNet: handledAccess}
	rid, _, errno := syscall.RawSyscall(sysLandlockCreateRuleset, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return nil
	}
	defer syscall.Close(int(rid))

	portAccess := make(map[int]uint64)

	if restrictConnect {
		connectPorts := cfg.AllowPorts
		for _, r := range cfg.AllowURLRules {
			if r.Port > 0 {
				found := false
				for _, p := range connectPorts {
					if p == r.Port {
						found = true
						break
					}
				}
				if !found {
					connectPorts = append(connectPorts, r.Port)
				}
			}
		}
		if len(connectPorts) == 0 && !cfg.DisableNetwork {
			connectPorts = []int{80, 443}
		}
		for _, p := range connectPorts {
			portAccess[p] |= landlockAccessNetConnectTCP
		}
		for p := 1; p <= 1024; p++ {
			portAccess[p] |= landlockAccessNetConnectTCP
		}
	}

	if restrictBind {
		for _, p := range bindPorts {
			portAccess[p] |= landlockAccessNetBindTCP
		}
	}

	for port, access := range portAccess {
		access &= handledAccess
		if access > 0 {
			ruleAttr := landlockNetPortAttr{AllowedAccess: access, Port: uint64(port)}
			syscall.Syscall6(sysLandlockAddRules, rid, uintptr(landlockRuleNetPort), uintptr(unsafe.Pointer(&ruleAttr)), 0, 0, 0)
		}
	}

	syscall.RawSyscall(sysLandlockRestrictSelf, rid, 0, 0)
	return nil
}

// landlockLayersRemaining returns the estimated number of remaining Landlock layers
// available. Landlock supports up to 16 stacked layers; returns -1 if the count
// cannot be determined. When fewer than 3 layers remain, subsequent restrict_self
// calls may fail with E2BIG.
func landlockLayersRemaining() int {
	// There is no direct kernel interface to query the current layer count.
	// We estimate by reading /proc/self/attr/landlock/layers when available.
	if data, err := os.ReadFile("/proc/self/attr/landlock/layers"); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		current := len(lines)
		if current > 0 {
			return 16 - current
		}
	}
	return -1
}

// warnLandlockLayers prints a diagnostic if Landlock layers are nearly exhausted.
func warnLandlockLayers() {
	remaining := landlockLayersRemaining()
	if remaining >= 0 && remaining < 3 {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: landlock layers nearly exhausted (%d remaining of 16). Subsequent sandboxing tools may fail with E2BIG.\n", remaining)
	}
}

// applyLandlockFilesystem applies Landlock filesystem access rules as a
// defense-in-depth layer within the mount namespace. It restricts file
// read, write, execute, and truncate operations to the declared read and
// write paths. This catches symlink escapes and missed bind-mount paths.
//
// When Landlock is unavailable or the ABI is too old, this function silently
// returns nil (best-effort, like applyLandlockNetwork). The calling code
// should log a warning.
func applyLandlockFilesystem(cfg config.ExecConfig) error {
	// Prevent unit tests from accidentally poisoning the Go test runner.
	if os.Getenv("SAFER_EXEC_CONFIG_PATH") == "" && os.Getenv("SAFER_EXEC_CONFIG") == "" && strings.HasSuffix(os.Args[0], ".test") {
		return nil
	}

	abi, _, errno := syscall.RawSyscall(sysLandlockCreateRuleset, 0, 0, landlockCreateRulesetVersion)
	if errno != 0 || abi < 3 {
		return nil
	}

	// Warn if layers are nearly exhausted
	warnLandlockLayers()

	// Select handled access rights based on ABI version
	handledFS := uint64(
		landlockAccessFSExecute |
			landlockAccessFSWriteFile |
			landlockAccessFSReadFile |
			landlockAccessFSReadDir |
			landlockAccessFSRemoveDir |
			landlockAccessFSRemoveFile |
			landlockAccessFSMakeChar |
			landlockAccessFSMakeDir |
			landlockAccessFSMakeReg |
			landlockAccessFSMakeSock |
			landlockAccessFSMakeFIFO |
			landlockAccessFSMakeBlock |
			landlockAccessFSMakeSym |
			landlockAccessFSRefer)
	if abi >= 3 {
		handledFS |= landlockAccessFSTruncate
	}

	attr := landlockRulesetAttr{HandledAccessFS: handledFS}
	rid, _, errno := syscall.RawSyscall(sysLandlockCreateRuleset, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("create landlock fs ruleset: %v", errno)
	}
	defer syscall.Close(int(rid))

	// Add path_beneath rules for read paths (read-only access)
	readOnlyAccess := uint64(
		landlockAccessFSExecute |
			landlockAccessFSReadFile |
			landlockAccessFSReadDir |
			landlockAccessFSRefer)
	for _, path := range cfg.ReadPaths {
		_ = addLandlockPathBeneath(int(rid), readOnlyAccess, path)
		// If the path no longer exists (e.g. it was inside the old root before pivot_root),
		// we silently skip it — Landlock rules for nonexistent paths are harmless.
	}

	// Add path_beneath rules for write paths (read-write access)
	writeAccess := handledFS // all handled access rights
	for _, path := range cfg.WritePaths {
		_ = addLandlockPathBeneath(int(rid), writeAccess, path)
	}

	// Apply the ruleset
	if _, _, errno := syscall.RawSyscall(sysLandlockRestrictSelf, rid, 0, 0); errno != 0 {
		return fmt.Errorf("landlock restrict self (fs): %v", errno)
	}

	return nil
}

// addLandlockPathBeneath adds a path_beneath rule for the given path and access rights.
// Returns nil on success; errors are non-fatal (the rule is simply skipped).
func addLandlockPathBeneath(rulesetFd int, allowedAccess uint64, path string) error {
	const oPath = 0x200000 // O_PATH on Linux
	fd, err := syscall.Open(path, oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	attr := landlockPathBeneathAttr{
		AllowedAccess: allowedAccess,
		ParentFd:      int32(fd),
	}
	_, _, errno := syscall.Syscall6(sysLandlockAddRules, uintptr(rulesetFd),
		uintptr(landlockRulePathBeneath), uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("add rule: %v", errno)
	}
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
	if os.Getenv("SAFER_EXEC_CONFIG_PATH") == "" && os.Getenv("SAFER_EXEC_CONFIG") == "" && strings.HasSuffix(os.Args[0], ".test") {
		return nil
	}

	// Set no_new_privs to allow seccomp filter without CAP_SYS_ADMIN
	// PR_SET_NO_NEW_PRIVS = 38
	syscall.Syscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0)

	blockCalls := []int{
		syscall.SYS_PTRACE, sysKCMP, syscall.SYS_UNSHARE, syscall.SYS_MOUNT, syscall.SYS_PIVOT_ROOT, sysSYSCALL,
		// Block privilege elevation (sudo/user/group changes)
		syscall.SYS_SETUID, syscall.SYS_SETGID, syscall.SYS_SETREUID, syscall.SYS_SETREGID,
		syscall.SYS_SETRESUID, syscall.SYS_SETRESGID, syscall.SYS_SETFSUID, syscall.SYS_SETFSGID,
		syscall.SYS_CAPSET,
		// Block file capability changes (setcap)
		syscall.SYS_SETXATTR, syscall.SYS_LSETXATTR, syscall.SYS_FSETXATTR,
		syscall.SYS_REMOVEXATTR, syscall.SYS_LREMOVEXATTR, syscall.SYS_FREMOVEXATTR,
		// Block eBPF, perf monitoring, tracepoints, userfaultfd, and kernel key manager
		sysBPF, syscall.SYS_PERF_EVENT_OPEN, sysUSERFAULTFD, syscall.SYS_KEYCTL,
		// Block time manipulation
		syscall.SYS_SETTIMEOFDAY, syscall.SYS_CLOCK_SETTIME, syscall.SYS_ADJTIMEX,
		// Block kernel logging / dmesg address leaks
		syscall.SYS_SYSLOG,
		// Block raw port IO and hardware control
		sysIOPERM, sysIOPL,
		// Block accounting, reboot, and chroot
		syscall.SYS_ACCT, syscall.SYS_REBOOT, syscall.SYS_KEXEC_LOAD, syscall.SYS_CHROOT,
	}
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

	// Socket filtering (UNIX domain socket AF_UNIX, Netlink AF_NETLINK, RAW SOCK_RAW)
	{
		const (
			afUnix       = 1
			afNetlink    = 16
			sockRaw      = 3
			sockTypeMask = 0xf
		)

		retKillOrTrapSocket := uint32(seccompRetErrno) | uint32(syscall.EACCES)
		if cfg.EnableAudit {
			trapVal := uint16(6 | (syscall.SYS_SOCKET&0xFF)<<8)
			retKillOrTrapSocket = uint32(seccompRetTrap) | uint32(trapVal)
		}

		insts = append(insts,
			syscall.SockFilter{Code: bpfJmpEq, Jf: 7, K: uint32(syscall.SYS_SOCKET)},
			syscall.SockFilter{Code: bpfLoadWordAbsolute, K: 16}, // args[0] (domain)
			syscall.SockFilter{Code: bpfJmpEq, Jt: 4, K: afUnix},
			syscall.SockFilter{Code: bpfJmpEq, Jt: 3, K: afNetlink},
			syscall.SockFilter{Code: bpfLoadWordAbsolute, K: 24}, // args[1] (type)
			syscall.SockFilter{Code: bpfAluAnd, K: sockTypeMask},
			syscall.SockFilter{Code: bpfJmpEq, Jt: 0, Jf: 1, K: sockRaw},
			syscall.SockFilter{Code: bpfJmpReturn, K: retKillOrTrapSocket},
			syscall.SockFilter{Code: bpfLoadWordAbsolute, K: 0}, // reload
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
	if e.Cipher != "" {
		entry["cipher"] = e.Cipher
	}
	if e.CipherIANAName != "" {
		entry["cipherIanaName"] = e.CipherIANAName
	}
	if e.CipherIANAID != 0 {
		entry["cipherIanaId"] = e.CipherIANAID
	}
	if e.TLSVersion != "" {
		entry["tlsVersion"] = e.TLSVersion
	}
	if e.CipherBits != 0 {
		entry["cipherBits"] = e.CipherBits
	}
	if e.CryptoLibrary != "" {
		entry["cryptoLibrary"] = e.CryptoLibrary
	}
	if e.CryptoLibraryVersion != "" {
		entry["cryptoLibraryVersion"] = e.CryptoLibraryVersion
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

// logAuditCryptoResult emits audit events for ciphers, libraries, and operations.
func logAuditCryptoResult(cfg config.ExecConfig, r *config.CryptoResult) {
	if r == nil {
		return
	}
	// Log ciphers
	for _, c := range r.Ciphers {
		entry := map[string]interface{}{
			"type":           "crypto-cipher",
			"name":           c.Name,
			"ianaName":       c.IANAName,
			"ianaId":         c.IANAID,
			"protocol":       c.Protocol,
			"bits":           c.Bits,
			"keyExchange":    c.KeyExchange,
			"authentication": c.Authentication,
			"encryption":     c.Encryption,
			"encryptionBits": c.EncryptionBits,
			"hash":           c.Hash,
			"mode":           c.Mode,
			"library":        c.Library,
			"libraryVersion": c.LibraryVersion,
			"pid":            c.PID,
		}
		data, _ := json.Marshal(entry)
		writeAuditRaw(data)
	}
	// Log libraries
	for _, l := range r.Libraries {
		entry := map[string]interface{}{
			"type":    "crypto-library",
			"name":    l.Name,
			"version": l.Version,
			"path":    l.Path,
			"source":  l.Source,
		}
		data, _ := json.Marshal(entry)
		writeAuditRaw(data)
	}
	// Log operations
	for _, o := range r.Operations {
		entry := map[string]interface{}{
			"type":           "crypto-operation",
			"operation":      o.Type,
			"algorithm":      o.Algorithm,
			"library":        o.Library,
			"libraryVersion": o.LibraryVersion,
			"pid":            o.PID,
			"count":          o.Count,
		}
		data, _ := json.Marshal(entry)
		writeAuditRaw(data)
	}
}

func writeAuditRaw(data []byte) {
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
		defer os.RemoveAll(filepath.Dir(auditCleanup))
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

func writeConfigToTempFile(data []byte) (string, error) {
	f, err := os.CreateTemp("", "safer-exec-config-*.json")
	if err != nil {
		return "", err
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()
	return f.Name(), nil
}

// isPathAllowed checks if a resolved path is within any of the allowed read or write paths.
// Used when resolving symlinks in read/write paths to prevent mounting targets
// that fall outside the declared policy.
func isPathAllowed(resolved string, readPaths, writePaths []string) bool {
	for _, rp := range readPaths {
		if resolved == rp || strings.HasPrefix(resolved, rp+"/") {
			return true
		}
	}
	for _, wp := range writePaths {
		if resolved == wp || strings.HasPrefix(resolved, wp+"/") {
			return true
		}
	}
	return false
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
		Arch:         runtime.GOARCH,
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
		{"time_namespace", "/proc/self/ns/time"},
		{"ipc_namespace", "/proc/self/ns/ipc"},
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
		// IO controller
		hasIO := false
		for _, c := range controllers {
			if c == "io" {
				hasIO = true
				break
			}
		}
		result.Capabilities["cgroup_v2_io"] = config.CapabilityInfo{Available: hasIO, Detail: "io controller"}
	} else {
		result.Capabilities["cgroup_v2"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
	}

	// Landlock
	if data, err := os.ReadFile("/sys/kernel/security/landlock/abi"); err == nil {
		abi := strings.TrimSpace(string(data))
		result.Capabilities["landlock"] = config.CapabilityInfo{Available: true, Detail: fmt.Sprintf("ABI v%s", abi)}
		// Landlock filesystem rules require ABI >= 3
		abiVer, convErr := strconv.Atoi(abi)
		if convErr == nil {
			fsAvailable := abiVer >= 3
			result.Capabilities["landlock_filesystem"] = config.CapabilityInfo{Available: fsAvailable, Detail: fmt.Sprintf("ABI v%d %s filesystem rules", abiVer, map[bool]string{true: "supports", false: "does not support"}[fsAvailable])}
		} else {
			result.Capabilities["landlock_filesystem"] = config.CapabilityInfo{Available: false, Detail: fmt.Sprintf("cannot parse ABI version: %s", abi)}
		}
	} else {
		result.Capabilities["landlock"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
		result.Capabilities["landlock_filesystem"] = config.CapabilityInfo{Available: false, Detail: "Landlock not available"}
	}

	// Landlock layer count
	if remaining := landlockLayersRemaining(); remaining >= 0 {
		detail := fmt.Sprintf("%d layers remaining (of 16)", remaining)
		available := remaining > 0
		result.Capabilities["landlock_layers_remaining"] = config.CapabilityInfo{Available: available, Detail: detail}
	}

	// AppArmor profile detection
	if data, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		enabled := strings.TrimSpace(string(data)) == "Y"
		result.Capabilities["apparmor"] = config.CapabilityInfo{Available: enabled, Detail: "AppArmor LSM enabled"}
		// Check if our profile is loaded
		if enabled {
			if profileData, profErr := os.ReadFile("/sys/kernel/security/apparmor/profiles"); profErr == nil {
				profileLoaded := strings.Contains(string(profileData), "safer-exec")
				result.Capabilities["apparmor_safer_exec"] = config.CapabilityInfo{Available: profileLoaded, Detail: "safer-exec AppArmor profile loaded"}
			}
		}
	} else {
		result.Capabilities["apparmor"] = config.CapabilityInfo{Available: false, Detail: "AppArmor not detected"}
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
	// stat /proc/1/root fails in containers (permission denied) even though
	// pivot_root works fine from within a mount namespace. Check mount namespace
	// availability as a reliable proxy: pivot_root has been available on all
	// Linux kernels since 2.3.99 and always works with a mount namespace.
	if result.Capabilities["mount_namespace"].Available {
		result.Capabilities["pivot_root"] = config.CapabilityInfo{Available: true, Detail: "pivot_root available via mount namespace"}
	} else {
		result.Capabilities["pivot_root"] = config.CapabilityInfo{Available: false, Detail: "mount namespace not available"}
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
			detail += " (CAP_BPF/CAP_SYS_ADMIN required)"
		case "2":
			detail += " (CAP_BPF/CAP_SYS_ADMIN required, locked)"
		}
		// Verify if we have actually load privilege or if root/sudo is needed
		if os.Getuid() != 0 {
			detail += " - WARNING: running as non-root user (UID != 0). eBPF tracing requires sudo or CAP_BPF+CAP_PERFMON+CAP_SYS_RESOURCE capabilities."
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

	// FIPS mode detection on Linux
	if data, err := os.ReadFile("/proc/sys/crypto/fips_enabled"); err == nil {
		fipsVal := strings.TrimSpace(string(data))
		if fipsVal == "1" {
			result.Capabilities["fips_detection"] = config.CapabilityInfo{Available: true, Detail: "FIPS mode enabled"}
		} else {
			result.Capabilities["fips_detection"] = config.CapabilityInfo{Available: true, Detail: "FIPS mode disabled (fips_enabled=0)"}
		}
	} else {
		result.Capabilities["fips_detection"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
	}

	// System-wide Go runtime binary check
	systemBin := "/usr/local/bin/safer-exec-rt"
	if _, err := os.Stat(systemBin); err == nil {
		result.Capabilities["system_runtime_binary"] = config.CapabilityInfo{Available: true, Detail: fmt.Sprintf("safer-exec-rt found at %s", systemBin)}
	} else {
		result.Capabilities["system_runtime_binary"] = config.CapabilityInfo{Available: false, Detail: fmt.Sprintf("safer-exec-rt NOT found at %s. Consider running: sudo cp <path>/safer-exec-rt %s", systemBin, systemBin)}
	}

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
	result.Features["io_limit"] = hasCGv2 && result.Capabilities["cgroup_v2_io"].Available
	result.Features["exec_control"] = hasSeccomp
	result.Features["fork_control"] = hasSeccomp
	result.Features["audit_tracing"] = hasSeccomp
	result.Features["filesystem_diff"] = true
	result.Features["learning_mode"] = fullIsolation || reducedIsolation
	result.Features["strict_mode"] = true
	result.Features["crypto_control"] = fullIsolation || reducedIsolation
	result.Features["fips_detection"] = result.Capabilities["fips_detection"].Available
	result.Features["gpu_control"] = fullIsolation || reducedIsolation
	result.Features["tpm_control"] = fullIsolation || reducedIsolation
	result.Features["antivm_spoofing"] = fullIsolation || reducedIsolation
	result.Features["trace_libraries"] = true
	result.Features["trace_http_urls"] = bpfForTrace
	result.Features["allow_url_rules"] = bpfForTrace
	result.Features["trace_crypto"] = bpfForTrace
	result.Features["time_isolation"] = result.Capabilities["time_namespace"].Available
	result.Features["ipc_isolation"] = result.Capabilities["ipc_namespace"].Available
	result.Features["landlock_filesystem"] = result.Capabilities["landlock_filesystem"].Available
	result.Features["apparmor_safer_exec"] = result.Capabilities["apparmor_safer_exec"].Available
	result.Features["proc_hidepid"] = true // fresh proc mount always attempted after pivot_root
	result.Features["lsm_bpf"] = bpfForTrace
	result.Features["crypto_ops_auditing"] = true

	return result
}
