//go:build linux

package main

import (
	"bytes"
	"encoding/base64"
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

	sysLOOKUP_DCOOKIE    = sysLOOKUP_DCOOKIE_unified
	sysFANOTIFY_INIT     = sysFANOTIFY_INIT_unified
	sysINOTIFY_INIT      = sysINOTIFY_INIT_unified
	sysINOTIFY_INIT1     = sysINOTIFY_INIT1_unified
	sysIO_URING_SETUP    = sysIO_URING_SETUP_unified
	sysIO_URING_ENTER    = sysIO_URING_ENTER_unified
	sysIO_URING_REGISTER = sysIO_URING_REGISTER_unified
	sysREQUEST_KEY       = sysREQUEST_KEY_unified
	sysPROCESS_VM_READV  = sysPROCESS_VM_READV_unified
	sysPROCESS_VM_WRITEV = sysPROCESS_VM_WRITEV_unified
	sysFINIT_MODULE      = sysFINIT_MODULE_unified

	sysGETRANDOM  = sysGETRANDOM_unified
	sysMEMBARRIER = sysMEMBARRIER_unified
	sysOPENAT2    = sysOPENAT2_unified
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

const oPathFlag = 0x200000 // O_PATH on Linux (not in syscall package)

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
	cmd := exec.Command("unshare", "-U", "-r", "/bin/true")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() != nil
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
	// Handle dry-run mode
	if cfg.EnableDryRun {
		return runDryRun(cfg)
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
	ProtocolProperties         *cbomProtoProps   `json:"protocolProperties,omitempty"`
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

type cbomProtoProps struct {
	Type         string            `json:"type"`
	Version      string            `json:"version,omitempty"`
	CipherSuites []cbomCipherSuite `json:"cipherSuites,omitempty"`
}

type cbomCipherSuite struct {
	Name       string   `json:"name"`
	Algorithms []string `json:"algorithms,omitempty"`
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

	seenProtocols := make(map[string]bool)
	for _, c := range cryptoResult.Ciphers {
		if c.Protocol == "" {
			continue
		}
		protoKey := c.Protocol
		if seenProtocols[protoKey] {
			continue
		}
		seenProtocols[protoKey] = true

		protoVersion := c.Protocol
		if strings.HasPrefix(protoVersion, "TLSv") {
			protoVersion = strings.TrimPrefix(protoVersion, "TLSv")
		}

		var suites []cbomCipherSuite
		for _, o := range cryptoResult.Ciphers {
			if o.Protocol == c.Protocol {
				name := o.IANAName
				if name == "" {
					name = o.Name
				}
				var algs []string
				if o.KeyExchange != "" && o.KeyExchange != "inline" {
					algs = append(algs, o.KeyExchange)
				}
				if o.Authentication != "" && o.Authentication != "inline" {
					algs = append(algs, o.Authentication)
				}
				if o.Encryption != "" {
					algs = append(algs, o.Encryption)
				}
				if o.Hash != "" {
					algs = append(algs, o.Hash)
				}
				suites = append(suites, cbomCipherSuite{
					Name:       name,
					Algorithms: algs,
				})
			}
		}

		doc.Components = append(doc.Components, cbomComponent{
			Type:    "cryptographic-asset",
			Name:    c.Protocol,
			Version: protoVersion,
			CryptoProperties: &cbomCryptoProps{
				AssetType: "protocol",
				ProtocolProperties: &cbomProtoProps{
					Type:         "tls",
					Version:      protoVersion,
					CipherSuites: suites,
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

// runDryRun executes the command in dry-run mode on Linux: clears allow lists
// so Landlock denies all filesystem and network operations, applies seccomp-bpf,
// and returns synthetic exit 0. The --init-dryrun flag handles the child side.
func runDryRun(cfg config.ExecConfig) error {
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding self: %w", err)
	}

	// Run self with --init-dryrun (applies Landlock deny-all + seccomp)
	cmd := exec.Command(selfPath, "--init-dryrun")
	cmd.Env = append(config.BuildEnv(cfg.Env), "SAFER_EXEC_CONFIG="+string(cfgJSON))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if cfg.WorkingDir != "" {
		cmd.Dir = cfg.WorkingDir
	}

	_ = cmd.Run() // ignore real exit code

	result := &config.DryRunResult{
		ExitCode: 0,
		Events:   []config.DryRunEvent{},
		Summary:  config.DryRunSummary{},
	}
	data, _ := json.Marshal(result)
	writeStructured(cfg, "DRYRUN:", data)
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
	cgroupPath, v1Paths, err := setupCgroup(cfg)
	if err != nil {
		return fmt.Errorf("setting up cgroup: %w", err)
	}
	if cgroupPath != "" {
		defer cleanupCgroup(cgroupPath)
	}
	if len(v1Paths) > 0 {
		defer cleanupCgroupV1(v1Paths)
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

	if err := applyLandlockScoped(cfg); err != nil {
		if cfg.Strict {
			return fmt.Errorf("landlock scoped: %w", err)
		}
		fmt.Fprintf(os.Stderr, "safer-exec: warning: landlock scoped: %v\n", err)
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

	cgroupPath, v1Paths, err := setupCgroup(cfg)
	if err != nil {
		return fmt.Errorf("setting up cgroup: %w", err)
	}
	if cgroupPath != "" {
		defer cleanupCgroup(cgroupPath)
	}
	if len(v1Paths) > 0 {
		defer cleanupCgroupV1(v1Paths)
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

	// MapToTargetUid: map UID 0 inside namespace to caller's real UID.
	// This makes the sandboxed process appear as the caller's UID (not root),
	// reducing the attack surface for root-in-namespace kernel bugs.
	if cfg.MapToTargetUid {
		uid := os.Getuid()
		gid := os.Getgid()
		uidMapping := fmt.Sprintf("0 %d 1", uid)
		gidMapping := fmt.Sprintf("0 %d 1", gid)
		if err := os.WriteFile("/proc/self/uid_map", []byte(uidMapping), 0); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: uid_map: %v\n", err)
		}
		if err := os.WriteFile("/proc/self/setgroups", []byte("deny"), 0); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: setgroups deny: %v\n", err)
		}
		if err := os.WriteFile("/proc/self/gid_map", []byte(gidMapping), 0); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: gid_map: %v\n", err)
		}
	}

	// When TraceLibraries is active and a precompiled .so helper exists, mount a
	// dedicated exec-capable tmpfs for the LD_AUDIT helper before Landlock locks
	// in. The sandbox root tmpfs is mounted MS_NOEXEC, so the dynamic linker
	// cannot mmap(PROT_EXEC) a .so placed directly in /tmp. We mount a fresh
	// tmpfs (without MS_NOEXEC) on a well-known path, add it to WritePaths so
	// Landlock explicitly permits it, and unmount+remove it on exit.
	const auditMountPath = "/tmp/safer-exec-ld-audit"
	if cfg.TraceLibraries && hasPrecompiledSo && len(auditHelperSo) > 0 && cfg.TraceTempDir == "" {
		if err := os.MkdirAll(auditMountPath, 0o700); err == nil {
			mountErr := syscall.Mount("tmpfs", auditMountPath, "tmpfs",
				syscall.MS_NODEV|syscall.MS_NOSUID, "size=4m,mode=0700")
			if mountErr == nil {
				cfg.TraceTempDir = auditMountPath
				cfg.WritePaths = append(cfg.WritePaths, auditMountPath)
				defer func() {
					syscall.Unmount(auditMountPath, syscall.MNT_DETACH)
					os.Remove(auditMountPath)
				}()
			} else {
				os.Remove(auditMountPath)
				fmt.Fprintf(os.Stderr, "safer-exec: warning: could not mount audit helper tmpfs: %v\n", mountErr)
			}
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

	if err := applyLandlockScoped(cfg); err != nil {
		if cfg.Strict {
			return fmt.Errorf("landlock scoped: %w", err)
		}
		fmt.Fprintf(os.Stderr, "safer-exec: warning: landlock scoped: %v\n", err)
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

	// Use the legacy direct-exec path by default. The new reaper-based
	// execution is opt-in via UseReaper because it is incompatible with
	// blockFork (seccomp kills the reaper's own clone syscall).
	if !cfg.UseReaper {
		return execCommand(cfg)
	}

	// Acquire advisory file locks for concurrent sandbox coordination.
	locks, lockErr := acquireFileLocks(cfg.LockFiles)
	if lockErr != nil {
		if cfg.Strict {
			return lockErr
		}
		fmt.Fprintf(os.Stderr, "safer-exec: warning: file lock: %v\n", lockErr)
	}
	defer releaseFileLocks(locks)

	// Emit JSON status notification on sandbox start.
	writeJsonStatus(cfg.JsonStatusFd, map[string]interface{}{
		"child-pid": os.Getpid(),
		"type":      "sandbox-start",
	})

	// Fork a PID 1 reaper to correctly handle child process exit codes and
	// zombie reaping within the PID namespace. The reaper (parent) waits for
	// the target command (child) and propagates its exit status.
	exitCode := runWithReaper(cfg)

	writeJsonStatus(cfg.JsonStatusFd, map[string]interface{}{
		"exit-code": exitCode,
		"type":      "sandbox-exit",
	})

	if exitCode != 0 {
		return &ExitError{Code: exitCode}
	}
	return nil
}

// runWithReaper forks a child process to execute the target command while the
// parent acts as PID 1, reaping orphaned children and propagating the target's
// exit code. This ensures correct process lifecycle management within the PID
// namespace.
func runWithReaper(cfg config.ExecConfig) int {
	// Prepare the full exec environment in the parent (before fork) so all
	// Go runtime operations (LD_AUDIT extraction, path resolution, env
	// construction) happen safely. Only raw syscalls are used post-fork.
	cmdPath, argv, env, prepCleanup, prepErr := prepareExecEnv(cfg)
	if prepErr != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: exec prep: %v\n", prepErr)
		_ = execCommand(cfg)
		return 1
	}
	defer prepCleanup()
	workingDir := cfg.WorkingDir

	pid, _, errno := syscall.RawSyscall(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0)
	if errno != 0 {
		fmt.Fprintf(os.Stderr, "safer-exec: fork failed: %v; falling back to direct exec\n", errno)
		_ = execCommand(cfg)
		return 1
	}

	if pid == 0 {
		closeChildFds()
		if workingDir != "" {
			syscall.Chdir(workingDir)
		}
		if cfg.DieWithParent {
			syscall.Syscall6(uintptr(syscall.SYS_PRCTL), uintptr(syscall.PR_SET_PDEATHSIG), uintptr(syscall.SIGKILL), 0, 0, 0, 0)
		}
		if cfg.NewSession {
			syscall.RawSyscall(syscall.SYS_SETSID, 0, 0, 0)
		}
		err := rawExecveat(cmdPath, argv, env)
		if err != nil {
			rawExecve(cmdPath, argv, env)
		}
		syscall.RawSyscall(syscall.SYS_EXIT, 1, 0, 0)
	}

	var wstatus syscall.WaitStatus
	exitCode := 1
	for {
		wpid, err := syscall.Wait4(-1, &wstatus, 0, nil)
		if err != nil || wpid < 0 {
			break
		}
		if wpid == int(pid) {
			if wstatus.Exited() {
				exitCode = wstatus.ExitStatus()
			} else if wstatus.Signaled() {
				exitCode = 128 + int(wstatus.Signal())
			}
			break
		}
	}
	return exitCode
}

// prepareExecEnv builds the final execution environment from the config:
// resolves the command path, checks blockExec, constructs the env (including
// LD_AUDIT injection for TraceLibraries), and returns a cleanup function.
// All Go runtime operations happen here — this must be called before any raw
// clone/fork.
func prepareExecEnv(cfg config.ExecConfig) (cmdPath string, argv []string, env []string, cleanup func(), err error) {
	noop := func() {}
	cmdBase := filepath.Base(cfg.Cmd)
	for _, blocked := range cfg.BlockExec {
		if blocked == cmdBase || blocked == cfg.Cmd {
			return "", nil, nil, noop, fmt.Errorf("command %s is blocked by blockExec policy", cfg.Cmd)
		}
	}
	cmdPath, err = exec.LookPath(cfg.Cmd)
	if err != nil {
		cmdPath = cfg.Cmd
	}
	env = config.BuildEnv(cfg.Env)
	var auditCleanup string
	if cfg.TraceLibraries {
		if !isMusl() {
			fmt.Fprintf(os.Stderr, "safer-exec: trace-libraries: enabled (LD_AUDIT).\n")
			var soPath string
			if hasPrecompiledSo && len(auditHelperSo) > 0 {
				var candidates []string
				if cfg.TraceTempDir != "" {
					candidates = append(candidates, cfg.TraceTempDir)
				}
				envVars := []string{"RUNNER_TEMP", "WORKSPACE_TMP", "CI_PROJECT_DIR", "BITBUCKET_CLONE_DIR", "CCI_TEMP_DIR", "TMPDIR", "TEMP", "TMP"}
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
	cleanup = func() {
		if auditCleanup != "" {
			os.RemoveAll(filepath.Dir(auditCleanup))
		}
	}
	argv = append([]string{cfg.Cmd}, cfg.Args...)
	return
}

// closeChildFds closes all file descriptors above stderr (fd 2) using only
// raw syscalls. Must be called only in a forked child where the Go runtime
// is undefined.
func closeChildFds() {
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
		return
	}
	maxFd := int(rlim.Cur)
	if maxFd > 4096 {
		maxFd = 4096
	}
	for fd := 3; fd < maxFd; fd++ {
		syscall.Close(fd)
	}
}

// rawExecveat invokes the execveat syscall directly. Returns the errno on
// failure; on success the calling process is replaced and never returns.
func rawExecveat(path string, argv, envp []string) error {
	pathPtr, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	argvPtrs, err := syscall.SlicePtrFromStrings(argv)
	if err != nil || len(argvPtrs) == 0 {
		return err
	}
	envpPtrs, _ := syscall.SlicePtrFromStrings(envp)
	_, _, errno := syscall.Syscall6(sysEXECVEAT, ^uintptr(100-1), uintptr(unsafe.Pointer(pathPtr)), uintptr(unsafe.Pointer(&argvPtrs[0])), uintptr(unsafe.Pointer(&envpPtrs[0])), 0, 0)
	return errno
}

// rawExecve invokes the execve syscall directly.
func rawExecve(path string, argv, envp []string) error {
	pathPtr, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	argvPtrs, err := syscall.SlicePtrFromStrings(argv)
	if err != nil || len(argvPtrs) == 0 {
		return err
	}
	envpPtrs, _ := syscall.SlicePtrFromStrings(envp)
	_, _, errno := syscall.Syscall(syscall.SYS_EXECVE, uintptr(unsafe.Pointer(pathPtr)), uintptr(unsafe.Pointer(&argvPtrs[0])), uintptr(unsafe.Pointer(&envpPtrs[0])))
	return errno
}

func setupCgroupV2Internal(cfg config.ExecConfig) (string, error) {
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

func setupCgroupV2(cfg config.ExecConfig) (string, error) {
	return setupCgroupV2Internal(cfg)
}

func setupCgroupV1(cfg config.ExecConfig) ([]string, error) {
	if cfg.MaxCPUCores == 0 && cfg.MaxMemoryMB == 0 && cfg.MaxProcesses == 0 &&
		cfg.MaxReadIOPS == 0 && cfg.MaxWriteIOPS == 0 && cfg.MaxReadBps == 0 && cfg.MaxWriteBps == 0 {
		return nil, nil
	}
	if _, err := os.Stat("/sys/fs/cgroup/memory"); err != nil {
		return nil, nil
	}

	pid := os.Getpid()
	pidStr := strconv.Itoa(pid)
	name := fmt.Sprintf("safer-exec-%d", pid)
	var cleanupPaths []string

	if cfg.MaxMemoryMB > 0 {
		memPath := filepath.Join("/sys/fs/cgroup/memory", name)
		if err := os.Mkdir(memPath, 0755); err == nil {
			cleanupPaths = append(cleanupPaths, memPath)
			memBytes := cfg.MaxMemoryMB * 1024 * 1024
			os.WriteFile(filepath.Join(memPath, "memory.limit_in_bytes"), []byte(fmt.Sprintf("%d\n", memBytes)), 0644)
			os.WriteFile(filepath.Join(memPath, "tasks"), []byte(pidStr+"\n"), 0644)
		}
	}

	if cfg.MaxCPUCores > 0 {
		cpuPath := filepath.Join("/sys/fs/cgroup/cpu", name)
		if err := os.Mkdir(cpuPath, 0755); err == nil {
			cleanupPaths = append(cleanupPaths, cpuPath)
			period := 100000
			quota := int(cfg.MaxCPUCores * float64(period))
			os.WriteFile(filepath.Join(cpuPath, "cpu.cfs_quota_us"), []byte(fmt.Sprintf("%d\n", quota)), 0644)
			os.WriteFile(filepath.Join(cpuPath, "cpu.cfs_period_us"), []byte(fmt.Sprintf("%d\n", period)), 0644)
			os.WriteFile(filepath.Join(cpuPath, "tasks"), []byte(pidStr+"\n"), 0644)
		}
	}

	if cfg.MaxProcesses > 0 {
		pidsPath := filepath.Join("/sys/fs/cgroup/pids", name)
		if err := os.Mkdir(pidsPath, 0755); err == nil {
			cleanupPaths = append(cleanupPaths, pidsPath)
			os.WriteFile(filepath.Join(pidsPath, "pids.max"), []byte(fmt.Sprintf("%d\n", cfg.MaxProcesses)), 0644)
			os.WriteFile(filepath.Join(pidsPath, "tasks"), []byte(pidStr+"\n"), 0644)
		}
	}

	if cfg.MaxReadBps > 0 || cfg.MaxWriteBps > 0 || cfg.MaxReadIOPS > 0 || cfg.MaxWriteIOPS > 0 {
		blkioPath := filepath.Join("/sys/fs/cgroup/blkio", name)
		if err := os.Mkdir(blkioPath, 0755); err == nil {
			cleanupPaths = append(cleanupPaths, blkioPath)
			if cfg.MaxReadBps > 0 {
				os.WriteFile(filepath.Join(blkioPath, "blkio.throttle.read_bps_device"), []byte(fmt.Sprintf("8:0 %d\n", cfg.MaxReadBps)), 0644)
			}
			if cfg.MaxWriteBps > 0 {
				os.WriteFile(filepath.Join(blkioPath, "blkio.throttle.write_bps_device"), []byte(fmt.Sprintf("8:0 %d\n", cfg.MaxWriteBps)), 0644)
			}
			if cfg.MaxReadIOPS > 0 {
				os.WriteFile(filepath.Join(blkioPath, "blkio.throttle.read_iops_device"), []byte(fmt.Sprintf("8:0 %d\n", cfg.MaxReadIOPS)), 0644)
			}
			if cfg.MaxWriteIOPS > 0 {
				os.WriteFile(filepath.Join(blkioPath, "blkio.throttle.write_iops_device"), []byte(fmt.Sprintf("8:0 %d\n", cfg.MaxWriteIOPS)), 0644)
			}
			os.WriteFile(filepath.Join(blkioPath, "tasks"), []byte(pidStr+"\n"), 0644)
		}
	}

	return cleanupPaths, nil
}

func setupCgroup(cfg config.ExecConfig) (string, []string, error) {
	cgroupV2Path, err := setupCgroupV2Internal(cfg)
	if err != nil {
		return "", nil, err
	}
	if cgroupV2Path != "" {
		return cgroupV2Path, nil, nil
	}
	v1Paths, err := setupCgroupV1(cfg)
	if err != nil {
		return "", nil, err
	}
	return "", v1Paths, nil
}

func cleanupCgroup(path string) {
	os.RemoveAll(path)
}

func cleanupCgroupV1(paths []string) {
	for _, p := range paths {
		os.RemoveAll(p)
	}
}

func setupFilesystem(cfg config.ExecConfig) error {
	// Make root mount slave so sandbox mounts never propagate to the host.
	syscall.Mount("", "/", "", syscall.MS_SLAVE|syscall.MS_REC, "")

	// ProtectSystem: automatically make system directories read-only.
	// This mirrors systemd's ProtectSystem=strict/full directive.
	if cfg.ProtectSystem == "strict" || cfg.ProtectSystem == "full" {
		systemPaths := []string{"/usr", "/boot", "/etc", "/lib"}
		if _, err := os.Stat("/lib64"); err == nil {
			systemPaths = append(systemPaths, "/lib64")
		}
		if cfg.ProtectSystem == "full" {
			systemPaths = append(systemPaths, "/")
		}
		for _, sp := range systemPaths {
			alreadyInRead := false
			for _, rp := range cfg.ReadPaths {
				if rp == sp {
					alreadyInRead = true
					break
				}
			}
			if !alreadyInRead {
				if _, err := os.Stat(sp); err == nil {
					cfg.ReadPaths = append(cfg.ReadPaths, sp)
				}
			}
		}
	}

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

	// ProtectHome: isolate $HOME directory inside the sandbox.
	// "read-only" adds home to read paths and removes from write paths.
	// "tmpfs" removes home from both read and write paths (mount handled in finalizeFilesystem).
	homeDir := os.Getenv("HOME")
	if cfg.ProtectHome == "read-only" && homeDir != "" {
		alreadyInRead := false
		for _, rp := range cfg.ReadPaths {
			if rp == homeDir {
				alreadyInRead = true
				break
			}
		}
		if !alreadyInRead {
			cfg.ReadPaths = append(cfg.ReadPaths, homeDir)
		}
		filteredWrites := make([]string, 0, len(cfg.WritePaths))
		for _, wp := range cfg.WritePaths {
			if wp != homeDir && !strings.HasPrefix(wp, homeDir+"/") {
				filteredWrites = append(filteredWrites, wp)
			}
		}
		cfg.WritePaths = filteredWrites
	} else if cfg.ProtectHome == "tmpfs" && homeDir != "" {
		filteredReads := make([]string, 0, len(cfg.ReadPaths))
		for _, rp := range cfg.ReadPaths {
			if rp != homeDir && !strings.HasPrefix(rp, homeDir+"/") {
				filteredReads = append(filteredReads, rp)
			}
		}
		cfg.ReadPaths = filteredReads
		filteredWrites := make([]string, 0, len(cfg.WritePaths))
		for _, wp := range cfg.WritePaths {
			if wp != homeDir && !strings.HasPrefix(wp, homeDir+"/") {
				filteredWrites = append(filteredWrites, wp)
			}
		}
		cfg.WritePaths = filteredWrites
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

	if cfg.PrivateTmp {
		os.MkdirAll(filepath.Join(newRoot, "var", "tmp"), 0o777)
	}

	// BindUseFd is opt-in (default false).
	bindUseFd := cfg.BindUseFd

	for _, path := range cfg.ReadPaths {
		if path == "/" {
			continue
		}
		target := filepath.Join(newRoot, path)
		fi, err := os.Lstat(path)
		if err != nil {
			continue
		}
		sourcePath := path
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
			sourcePath = resolved
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

		if err := bindMount(sourcePath, target, bindUseFd); err != nil {
			if cfg.Strict {
				return fmt.Errorf("bind mount %s: %w", sourcePath, err)
			}
			fmt.Fprintf(os.Stderr, "safer-exec: warning: bind mount %s: %v\n", sourcePath, err)
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
		sourcePath := path
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
			sourcePath = resolved
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

		if err := bindMount(sourcePath, target, bindUseFd); err != nil {
			if cfg.Strict {
				return fmt.Errorf("bind mount %s: %w", sourcePath, err)
			}
			fmt.Fprintf(os.Stderr, "safer-exec: warning: bind mount %s: %v\n", sourcePath, err)
			continue
		}
	}

	// After all bind mounts are established, enforce that every submount
	// under every read-only target is also read-only. Reading mountinfo once
	// and remounting in a single pass avoids quadratic overhead when many
	// read paths are declared (e.g. policies with 16+ paths).
	if cfg.SubmountEnforce {
		enforceAllSubmountsReadOnly(cfg.ReadPaths)
	}

	// Bind pre-opened FDs into the sandbox.
	for _, spec := range cfg.BindFds {
		target := filepath.Join(newRoot, spec.Target)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			if cfg.Strict {
				return fmt.Errorf("bind fd mkdir %s: %w", filepath.Dir(target), err)
			}
			continue
		}
		f, _ := os.Create(target)
		if f != nil {
			f.Close()
		}
		if err := bindMountFd(spec.Fd, target, spec.ReadOnly); err != nil {
			if cfg.Strict {
				return fmt.Errorf("bind fd %d to %s: %w", spec.Fd, spec.Target, err)
			}
			fmt.Fprintf(os.Stderr, "safer-exec: warning: bind fd %d to %s: %v\n", spec.Fd, spec.Target, err)
		}
	}

	return finalizeFilesystem(newRoot, cfg)
}

// bindMount performs a recursive bind mount from source to target. When useFd
// is true, the source is opened first via O_PATH and mounted through
// /proc/self/fd/N. After mounting, fstat(fd) is compared against lstat(target)
// to detect TOCTTOU races where the path was swapped between resolution and
// the mount syscall.
func bindMount(source, target string, useFd bool) error {
	if !useFd {
		return syscall.Mount(source, target, "", syscall.MS_BIND|syscall.MS_REC, "")
	}
	fd, err := syscall.Open(source, oPathFlag|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	if err := syscall.Mount(fdPath, target, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return err
	}
	var fdStat, targetStat syscall.Stat_t
	if err := syscall.Fstat(fd, &fdStat); err != nil {
		return nil
	}
	if err := syscall.Lstat(target, &targetStat); err != nil {
		return nil
	}
	if fdStat.Ino != targetStat.Ino || fdStat.Dev != targetStat.Dev {
		syscall.Unmount(target, syscall.MNT_DETACH)
		return fmt.Errorf("path %s swapped between open and mount", source)
	}
	return nil
}

// bindMountFd bind-mounts a file descriptor (from the parent namespace) to
// a target path inside the sandbox. The fd must already be opened. This is
// used for privilege-separated FD handoff where a privileged parent opens
// special files and passes fds to the sandbox via BindFds.
func bindMountFd(fd int, target string, readOnly bool) error {
	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	flags := uintptr(syscall.MS_BIND | syscall.MS_REC)
	if err := syscall.Mount(fdPath, target, "", flags, ""); err != nil {
		return err
	}
	if readOnly {
		return syscall.Mount("", target, "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY, "")
	}
	return nil
}

// enforceAllSubmountsReadOnly reads /proc/self/mountinfo once and remounts
// every submount under any of the given readPaths as read-only. This is a
// batched replacement for per-path enforceSubmountReadOnly, avoiding quadratic
// overhead from repeated mountinfo parsing when many read paths are declared.
func enforceAllSubmountsReadOnly(readPaths []string) {
	if len(readPaths) == 0 {
		return
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return
	}
	// Track already-remounted paths to avoid redundant syscalls when
	// multiple read paths overlap (e.g. /usr and /usr/lib both cover
	// submount /usr/lib/python3).
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		mp := fields[4]
		if seen[mp] {
			continue
		}
		for _, rp := range readPaths {
			if mp == rp || strings.HasPrefix(mp, rp+"/") {
				seen[mp] = true
				syscall.Mount("", mp, "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY, "")
				break
			}
		}
	}
}

// enforceSubmountReadOnly parses /proc/self/mountinfo to discover submounts
// under target and individually remounts each as read-only. This closes an
// MS_REC loophole where the kernel remount propagation may leave existing
// submounts writable after a parent remount to read-only.
func enforceSubmountReadOnly(target string) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		mp := fields[4]
		if mp == target || strings.HasPrefix(mp, target+"/") {
			syscall.Mount("", mp, "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY, "")
		}
	}
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
	putOld := filepath.Join(newRoot, ".oldroot")
	_ = os.Mkdir(putOld, 0o755)

	// First pivot_root: make the tmpfs newRoot the new filesystem root.
	if err := syscall.PivotRoot(newRoot, putOld); err != nil {
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

	// Make old root private to break mount propagation before unmounting.
	syscall.Mount("", "/.oldroot", "", syscall.MS_PRIVATE|syscall.MS_REC, "")
	_ = syscall.Unmount("/.oldroot", syscall.MNT_DETACH)
	_ = os.RemoveAll("/.oldroot")

	// PrivateTmp: replace /tmp and /var/tmp with fresh tmpfs mounts so
	// temporary files are not shared with the host or other sandbox instances.
	if cfg.PrivateTmp {
		_ = syscall.Unmount("/tmp", syscall.MNT_DETACH)
		_ = syscall.Mount("tmpfs", "/tmp", "tmpfs", syscall.MS_NODEV|syscall.MS_NOEXEC|syscall.MS_NOSUID, "size=32m")
		_ = os.MkdirAll("/var/tmp", 01777)
		_ = syscall.Unmount("/var/tmp", syscall.MNT_DETACH)
		_ = syscall.Mount("tmpfs", "/var/tmp", "tmpfs", syscall.MS_NODEV|syscall.MS_NOEXEC|syscall.MS_NOSUID, "size=32m")
	}

	// ProtectHome tmpfs: replace $HOME with blank tmpfs so the home
	// directory is ephemeral and empty.
	if cfg.ProtectHome == "tmpfs" {
		if home := os.Getenv("HOME"); home != "" {
			_ = os.MkdirAll(home, 01755)
			_ = syscall.Unmount(home, syscall.MNT_DETACH)
			_ = syscall.Mount("tmpfs", home, "tmpfs", syscall.MS_NODEV|syscall.MS_NOEXEC|syscall.MS_NOSUID, "size=16m")
		}
	}

	// Mount a fresh proc filesystem with hidepid=2 to prevent
	// leaking host process information through /proc.
	// subset=pid restricts the view to PID-related entries only.
	if _, err := os.Stat("/proc"); err == nil {
		_ = syscall.Unmount("/proc", syscall.MNT_DETACH)
	}
	_ = os.MkdirAll("/proc", 0o555)
	if err := syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, "hidepid=2,subset=pid"); err != nil {
		_ = syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, "")
	}

	// Harden /proc: cover dangerous writable entries with read-only bind mounts.
	if cfg.ProcHardening {
		dangerousProcs := []string{"/proc/sys", "/proc/sysrq-trigger", "/proc/irq", "/proc/bus"}
		for _, dp := range dangerousProcs {
			if _, err := os.Stat(dp); err == nil {
				syscall.Mount(dp, dp, "", syscall.MS_BIND|syscall.MS_REC, "")
				syscall.Mount(dp, dp, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, "")
			}
		}
	}

	// Set up minimal /dev with essential device nodes unless disabled.
	if cfg.SetUpDev {
		if err := setupDev(cfg); err != nil {
			if cfg.Strict {
				return fmt.Errorf("dev setup: %w", err)
			}
			fmt.Fprintf(os.Stderr, "safer-exec: warning: dev setup: %v\n", err)
		}
	}

	return nil
}

// setupDev creates a minimal /dev inside the sandbox with essential device
// nodes (/dev/null, /dev/zero, /dev/full, /dev/random, /dev/urandom, /dev/tty),
// /dev/pts, /dev/shm, and stdio symlinks. Device nodes are bind-mounted from
// the host; only those that exist on the host are created.
func setupDev(cfg config.ExecConfig) error {
	if _, err := os.Stat("/dev"); err == nil {
		syscall.Unmount("/dev", syscall.MNT_DETACH)
	}
	_ = os.MkdirAll("/dev", 0o755)
	if err := syscall.Mount("tmpfs", "/dev", "tmpfs", syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, "size=2m"); err != nil {
		return err
	}

	essentialDevices := []string{"null", "zero", "full", "random", "urandom", "tty"}
	for _, devName := range essentialDevices {
		hostPath := "/dev/" + devName
		sandboxPath := "/dev/" + devName
		if _, err := os.Stat(hostPath); err != nil {
			continue
		}
		f, _ := os.Create(sandboxPath)
		if f != nil {
			f.Close()
		}
		syscall.Mount(hostPath, sandboxPath, "", syscall.MS_BIND, "")
	}

	os.Symlink("/proc/self/fd/0", "/dev/stdin")
	os.Symlink("/proc/self/fd/1", "/dev/stdout")
	os.Symlink("/proc/self/fd/2", "/dev/stderr")
	os.Symlink("/proc/self/fd", "/dev/fd")

	_ = os.MkdirAll("/dev/shm", 0o777)
	return nil
}

type landlockRulesetAttr struct{ HandledAccessFS, HandledAccessNet, Scoped uint64 }
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

// Landlock ABI v5+ IOCTL device control (Linux 6.12+).
const landlockAccessFSIoctlDev = 1 << 15

// UDP network flags removed: LANDLOCK_ACCESS_NET_BIND_UDP and
// LANDLOCK_ACCESS_NET_CONNECT_UDP do not exist in any released kernel.
// When they land, add them here gated behind the appropriate ABI version.

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
		return fmt.Errorf("create landlock net ruleset: %v", errno)
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
	}

	// When URL rules are present, always permit ports 80 and 443 at the Landlock
	// layer so the eBPF tracer can capture HTTP(S) requests for URL-rule matching.
	// Landlock is coarse (port-level); URL rules are fine-grained (host/path/port).
	// Without this, a rule like {port:8443} would block Landlock port 443 before
	// the tracer can see the request, preventing url-violation from firing.
	if restrictConnect && len(cfg.AllowURLRules) > 0 && !cfg.DisableNetwork {
		portAccess[80] |= landlockAccessNetConnectTCP
		portAccess[443] |= landlockAccessNetConnectTCP
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

	if _, _, errno := syscall.RawSyscall(sysLandlockRestrictSelf, rid, 0, 0); errno != 0 {
		return fmt.Errorf("landlock restrict self (net): %v", errno)
	}
	return nil
}

// applyLandlockScoped applies Landlock scoped rules (ABI v5+) for IPC restrictions.
// Scoped rules prevent the sandbox from signaling, connecting abstract Unix sockets,
// or ptracing processes outside the sandbox. Linux 6.12+.
//
// The scoped Landlock rules API is still evolving. This function detects ABI v5
// and reports availability via diagnostics, but actual enforcement is deferred
// until the kernel interface stabilizes.
func applyLandlockScoped(cfg config.ExecConfig) error {
	// Prevent unit tests from accidentally poisoning the Go test runner.
	if os.Getenv("SAFER_EXEC_CONFIG_PATH") == "" && os.Getenv("SAFER_EXEC_CONFIG") == "" && strings.HasSuffix(os.Args[0], ".test") {
		return nil
	}

	abiVer := 0
	if data, err := os.ReadFile("/sys/kernel/security/landlock/abi"); err == nil {
		if v, convErr := strconv.Atoi(strings.TrimSpace(string(data))); convErr == nil {
			abiVer = v
		}
	}
	if abiVer < 6 {
		return nil
	}

	const (
		landlockScopeAbstractUnixSocket = 1 << 0
		landlockScopeSignal             = 1 << 1
	)

	_ = landlockScopeSignal
	_ = landlockScopeAbstractUnixSocket

	// TODO: create a scoped ruleset when kernel ABI stabilizes.
	// The scoped ruleset uses a different ruleset type with its own
	// attribute struct. The exact syscall interface is still evolving
	// in kernel 6.12+.

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
	if abi >= 5 {
		handledFS |= landlockAccessFSIoctlDev
	}

	attr := landlockRulesetAttr{HandledAccessFS: handledFS}
	rid, _, errno := syscall.RawSyscall(sysLandlockCreateRuleset, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("create landlock fs ruleset: %v", errno)
	}
	defer syscall.Close(int(rid))

	// Access masks split by inode type: Landlock rejects rights that don't apply
	// to the inode kind (e.g. READ_DIR on a regular file returns EINVAL and
	// silently drops the rule, leaving the file inaccessible).
	readOnlyDirAccess := uint64(
		landlockAccessFSExecute |
			landlockAccessFSReadFile |
			landlockAccessFSReadDir |
			landlockAccessFSRefer)
	readOnlyFileAccess := uint64(
		landlockAccessFSExecute |
			landlockAccessFSReadFile)

	for _, path := range cfg.ReadPaths {
		fi, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			_ = addLandlockPathBeneath(int(rid), readOnlyDirAccess, path)
		} else {
			_ = addLandlockPathBeneath(int(rid), readOnlyFileAccess, path)
		}
	}

	// /dev/null is a universal write sink (2>/dev/null, shell redirects).
	// Grant write access unconditionally without opening the whole /dev tree.
	devNullAccess := uint64(landlockAccessFSReadFile | landlockAccessFSWriteFile)
	_ = addLandlockPathBeneath(int(rid), devNullAccess, "/dev/null")

	// Write paths: strip directory-only rights when the target is a regular file.
	writeDirAccess := handledFS
	writeFileAccess := handledFS &^ uint64(
		landlockAccessFSReadDir|
			landlockAccessFSRemoveDir|
			landlockAccessFSMakeChar|
			landlockAccessFSMakeDir|
			landlockAccessFSMakeReg|
			landlockAccessFSMakeSock|
			landlockAccessFSMakeFIFO|
			landlockAccessFSMakeBlock|
			landlockAccessFSMakeSym)
	for _, path := range cfg.WritePaths {
		fi, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			_ = addLandlockPathBeneath(int(rid), writeDirAccess, path)
		} else {
			_ = addLandlockPathBeneath(int(rid), writeFileAccess, path)
		}
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
		// Block execution domain changes and kernel profiling
		syscall.SYS_PERSONALITY, sysLOOKUP_DCOOKIE,
		// Block privilege elevation (sudo/user/group changes)
		syscall.SYS_SETUID, syscall.SYS_SETGID, syscall.SYS_SETREUID, syscall.SYS_SETREGID,
		syscall.SYS_SETRESUID, syscall.SYS_SETRESGID, syscall.SYS_SETFSUID, syscall.SYS_SETFSGID,
		syscall.SYS_CAPSET,
		// Block file capability changes (setcap)
		syscall.SYS_SETXATTR, syscall.SYS_LSETXATTR, syscall.SYS_FSETXATTR,
		syscall.SYS_REMOVEXATTR, syscall.SYS_LREMOVEXATTR, syscall.SYS_FREMOVEXATTR,
		// Block eBPF, perf monitoring, tracepoints, userfaultfd, and kernel key manager
		sysBPF, syscall.SYS_PERF_EVENT_OPEN, sysUSERFAULTFD, syscall.SYS_KEYCTL,
		// Block file change monitoring (fanotify + inotify)
		sysFANOTIFY_INIT, sysINOTIFY_INIT, sysINOTIFY_INIT1,
		syscall.SYS_INOTIFY_ADD_WATCH, syscall.SYS_INOTIFY_RM_WATCH,
		// Block io_uring (can bypass seccomp on some kernels)
		sysIO_URING_SETUP, sysIO_URING_ENTER, sysIO_URING_REGISTER,
		// Block cross-process memory access
		sysPROCESS_VM_READV, sysPROCESS_VM_WRITEV,
		// Block kernel module loading
		syscall.SYS_DELETE_MODULE, syscall.SYS_INIT_MODULE, sysFINIT_MODULE,
		// Block disk quota manipulation
		syscall.SYS_QUOTACTL,
		// Block swap device control
		syscall.SYS_SWAPOFF, syscall.SYS_SWAPON,
		// Block kernel key management (supplements keyctl)
		sysREQUEST_KEY,
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
		// Always return EPERM for the default hardening blocklist.
		// This allows runtime engines (like Node.js/V8, Go, Python) to handle
		// the permission error gracefully and fallback, rather than crashing
		// with SIGSYS (bad system call) when audit is enabled.
		insts = append(insts, syscall.SockFilter{Code: bpfJmpReturn, K: uint32(seccompRetErrno) | uint32(syscall.EPERM)})
	}
	insts = append(insts, syscall.SockFilter{Code: bpfJmpReturn, K: seccompRetAllow})

	prog := syscall.SockFprog{Len: uint16(len(insts)), Filter: &insts[0]}
	_, _, errno := syscall.RawSyscall(sysSeccomp, 1, 0, uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		return fmt.Errorf("seccomp filter: %v", errno)
	}

	// Stack additional seccomp filters from policy (evaluated before base filter
	// by LIFO kernel order). This enables composition across organizational
	// boundaries — a base security policy, org-mandated filter, and
	// project-specific filter can all coexist.
	for i := len(cfg.SeccompFilters) - 1; i >= 0; i-- {
		spec := cfg.SeccompFilters[i]
		var extraProg syscall.SockFprog
		var extraInsts []syscall.SockFilter

		if spec.Path != "" {
			data, err := os.ReadFile(spec.Path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "safer-exec: warning: seccomp filter path %s: %v\n", spec.Path, err)
				continue
			}
			extraInsts = parseSeccompProgram(data)
		} else if spec.Program != "" {
			decoded, err := decodeBase64Seccomp(spec.Program)
			if err != nil {
				fmt.Fprintf(os.Stderr, "safer-exec: warning: seccomp filter decode: %v\n", err)
				continue
			}
			extraInsts = decoded
		} else if spec.Policy != "" {
			var err error
			extraInsts, err = compileKafelPolicy(spec.Policy)
			if err != nil {
				fmt.Fprintf(os.Stderr, "safer-exec: warning: seccomp policy compile: %v\n", err)
				continue
			}
		}
		if len(extraInsts) == 0 {
			continue
		}
		extraProg = syscall.SockFprog{Len: uint16(len(extraInsts)), Filter: &extraInsts[0]}
		_, _, errno := syscall.RawSyscall(sysSeccomp, 1, 0, uintptr(unsafe.Pointer(&extraProg)))
		if errno != 0 {
			if cfg.Strict {
				return fmt.Errorf("stack seccomp filter %d: %v", i, errno)
			}
			fmt.Fprintf(os.Stderr, "safer-exec: warning: stack seccomp filter %d: %v\n", i, errno)
		}
	}

	return nil
}

// parseSeccompProgram reads raw BPF bytecode from data and converts it to a
// slice of syscall.SockFilter. Each SockFilter is 8 bytes (2 bytes code,
// 1 byte jt, 1 byte jf, 4 bytes k). Returns nil if data is malformed.
func parseSeccompProgram(data []byte) []syscall.SockFilter {
	if len(data)%8 != 0 || len(data) == 0 {
		return nil
	}
	n := len(data) / 8
	filters := make([]syscall.SockFilter, n)
	for i := 0; i < n; i++ {
		off := i * 8
		code := uint16(data[off]) | uint16(data[off+1])<<8
		jt := data[off+2]
		jf := data[off+3]
		k := uint32(data[off+4]) | uint32(data[off+5])<<8 | uint32(data[off+6])<<16 | uint32(data[off+7])<<24
		filters[i] = syscall.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
	}
	return filters
}

// decodeBase64Seccomp decodes a base64-encoded BPF program string to SockFilter
// slice. The encoded string uses standard base64 (RFC 4648). Returns nil on
// decode errors or if the decoded data is not a multiple of 8 bytes.
func decodeBase64Seccomp(encoded string) ([]syscall.SockFilter, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("decoded length %d is not a multiple of 8", len(data))
	}
	return parseSeccompProgram(data), nil
}

// compileKafelPolicy compiles a minimal Kafel-style policy string to BPF bytecode.
// Supported syntax:
//
//	"ALLOW syscall1, syscall2, ...; DEFAULT KILL|ERRNO"
//	"KILL syscall1, syscall2; DEFAULT ALLOW"
//
// Valid actions: ALLOW, KILL, ERRNO(n)
// Masks for ALLOW/KILL are implicit (match syscall number exactly).
//
// This is a simplified subset of the full Kafel grammar sufficient for
// common policy expression needs. For complex policies, use raw BPF or
// base64-encoded programs via SeccompFilterSpec.Program.
func compileKafelPolicy(policy string) ([]syscall.SockFilter, error) {
	policy = strings.TrimSpace(policy)
	if policy == "" {
		return nil, fmt.Errorf("empty policy")
	}

	actions := map[string]uint32{
		"ALLOW": seccompRetAllow,
		"KILL":  seccompRetKill,
	}

	statements := strings.Split(policy, ";")
	var defaultAction uint32 = seccompRetKill
	var ruleSets []struct {
		syscalls []int
		action   uint32
	}

	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}

		if strings.HasPrefix(strings.ToUpper(stmt), "DEFAULT ") {
			actionStr := strings.TrimSpace(stmt[8:])
			actionStr = strings.ToUpper(actionStr)
			if strings.HasPrefix(actionStr, "ERRNO") {
				errnoStr := strings.TrimPrefix(actionStr, "ERRNO")
				errnoStr = strings.Trim(errnoStr, "() ")
				errnoVal, err := strconv.Atoi(errnoStr)
				if err != nil {
					return nil, fmt.Errorf("invalid ERRNO value: %s", errnoStr)
				}
				defaultAction = uint32(seccompRetErrno) | uint32(errnoVal)
			} else if action, ok := actions[actionStr]; ok {
				defaultAction = action
			} else {
				return nil, fmt.Errorf("unknown default action: %s", actionStr)
			}
			continue
		}

		parts := strings.SplitN(stmt, " ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid statement: %s", stmt)
		}
		actionStr := strings.ToUpper(strings.TrimSpace(parts[0]))
		syscallList := strings.TrimSpace(parts[1])

		var action uint32
		if strings.HasPrefix(actionStr, "ERRNO") {
			errnoStr := strings.TrimPrefix(actionStr, "ERRNO")
			errnoStr = strings.Trim(errnoStr, "() ")
			errnoVal, err := strconv.Atoi(errnoStr)
			if err != nil {
				return nil, fmt.Errorf("invalid ERRNO value: %s", errnoStr)
			}
			action = uint32(seccompRetErrno) | uint32(errnoVal)
		} else if a, ok := actions[actionStr]; ok {
			action = a
		} else {
			return nil, fmt.Errorf("unknown action: %s", actionStr)
		}

		var syscalls []int
		for _, name := range strings.Split(syscallList, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			nr := resolveSyscallName(name)
			if nr == -1 {
				return nil, fmt.Errorf("unknown syscall: %s", name)
			}
			syscalls = append(syscalls, nr)
		}
		if len(syscalls) > 0 {
			ruleSets = append(ruleSets, struct {
				syscalls []int
				action   uint32
			}{syscalls, action})
		}
	}

	var insts []syscall.SockFilter
	insts = append(insts, syscall.SockFilter{Code: bpfLoadWordAbsolute, K: 0})

	for _, rs := range ruleSets {
		for i, nr := range rs.syscalls {
			var jf uint8 = 1
			if i == len(rs.syscalls)-1 {
				jf = 2
			}
			insts = append(insts, syscall.SockFilter{Code: bpfJmpEq, Jt: 0, Jf: jf, K: uint32(nr)})
			if i == len(rs.syscalls)-1 {
				insts = append(insts, syscall.SockFilter{Code: bpfJmpReturn, K: rs.action})
			}
		}
	}
	insts = append(insts, syscall.SockFilter{Code: bpfJmpReturn, K: defaultAction})

	return insts, nil
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
	cmdPath, argv, env, prepCleanup, prepErr := prepareExecEnv(cfg)
	if prepErr != nil {
		return prepErr
	}
	defer prepCleanup()

	if cfg.WorkingDir != "" {
		_ = os.Chdir(cfg.WorkingDir)
	}

	// TraceLibraries diagnostic messages are printed by prepareExecEnv.
	// On musl we emit a fallback diagnostic here.
	if cfg.TraceLibraries && isMusl() {
		fmt.Fprintf(os.Stderr, "safer-exec: trace-libraries: enabled (proc maps fallback under musl).\n")
	}

	// Signal the sandboxed process with SIGKILL when the parent dies.
	// This prevents orphaned sandbox processes in CI/CD cancellation scenarios.
	if cfg.DieWithParent {
		_, _, errno := syscall.Syscall6(uintptr(syscall.SYS_PRCTL), uintptr(syscall.PR_SET_PDEATHSIG), uintptr(syscall.SIGKILL), 0, 0, 0, 0)
		if errno != 0 {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: PR_SET_PDEATHSIG: %v\n", errno)
		}
	}
	// Disconnect from the controlling terminal to prevent terminal-based
	// signal injection (SIGHUP, SIGINT) and TTY ioctl attacks.
	if cfg.NewSession {
		_, _, errno := syscall.RawSyscall(syscall.SYS_SETSID, 0, 0, 0)
		if errno != 0 {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: setsid: %v\n", errno)
		}
	}

	// Try execveat to allow seccomp filtering to block standard execve
	err := execveat(-100, cmdPath, argv, env, 0)
	if err == syscall.ENOSYS || err == syscall.EPERM || err == syscall.EACCES {
		err = syscall.Exec(cmdPath, argv, env)
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
	// Explicitly allow systemd resolved files which are symlink targets of /etc/resolv.conf
	if resolved == "/run/systemd/resolve/stub-resolv.conf" || resolved == "/run/systemd/resolve/resolv.conf" {
		return true
	}
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

// acquireFileLocks acquires advisory locks on each path in lockFiles.
// Shared (read) locks are used by default; exclusive (write) locks are used
// when spec.Exclusive is true. The locks are held for the lifetime of the
// returned file handles. Close the files to release. This enables concurrent
// sandbox coordination when multiple processes need serialized access to
// shared directories.
func acquireFileLocks(lockFiles []config.LockFileSpec) ([]*os.File, error) {
	if len(lockFiles) == 0 {
		return nil, nil
	}
	var files []*os.File
	for _, spec := range lockFiles {
		f, err := os.OpenFile(spec.Path, os.O_RDONLY|os.O_CREATE, 0o644)
		if err != nil {
			for _, prev := range files {
				prev.Close()
			}
			return nil, fmt.Errorf("lock-file %s: %w", spec.Path, err)
		}
		lockOp := syscall.LOCK_SH
		if spec.Exclusive {
			lockOp = syscall.LOCK_EX
		}
		if err := syscall.Flock(int(f.Fd()), lockOp); err != nil {
			f.Close()
			for _, prev := range files {
				prev.Close()
			}
			return nil, fmt.Errorf("flock %s: %w", spec.Path, err)
		}
		files = append(files, f)
	}
	return files, nil
}

// releaseFileLocks closes all lock file handles, releasing the advisory locks.
func releaseFileLocks(files []*os.File) {
	for _, f := range files {
		f.Close()
	}
}

// writeJsonStatus writes a JSON object to the status fd if configured.
// Each write is a single JSON-lines entry terminated by newline.
func writeJsonStatus(fd int, msg map[string]interface{}) {
	if fd <= 0 {
		return
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	data = append(data, '\n')
	syscall.Write(fd, data)
}

// closeExtraFds closes all file descriptors above stderr (fd 2) that the
// process may have inherited. Leaked fds can expose internal state, hold
// locks, or enable sandbox escapes via /proc/self/fd. Must be called in the
// child process just before exec.
func closeExtraFds() {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return
	}
	for _, entry := range entries {
		fd, convErr := strconv.Atoi(entry.Name())
		if convErr != nil || fd <= 2 {
			continue
		}
		syscall.Close(fd)
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

	// cgroup v1
	if _, err := os.Stat("/sys/fs/cgroup/memory"); err == nil {
		result.Capabilities["cgroup_v1"] = config.CapabilityInfo{Available: true, Detail: "cgroup v1 memory controller present"}
		if _, cpuErr := os.Stat("/sys/fs/cgroup/cpu"); cpuErr == nil {
			result.Capabilities["cgroup_v1_cpu"] = config.CapabilityInfo{Available: true, Detail: "cgroup v1 cpu controller present"}
		} else {
			result.Capabilities["cgroup_v1_cpu"] = config.CapabilityInfo{Available: false, Detail: cpuErr.Error()}
		}
		if _, pidsErr := os.Stat("/sys/fs/cgroup/pids"); pidsErr == nil {
			result.Capabilities["cgroup_v1_pids"] = config.CapabilityInfo{Available: true, Detail: "cgroup v1 pids controller present"}
		} else {
			result.Capabilities["cgroup_v1_pids"] = config.CapabilityInfo{Available: false, Detail: pidsErr.Error()}
		}
		if _, blkioErr := os.Stat("/sys/fs/cgroup/blkio"); blkioErr == nil {
			result.Capabilities["cgroup_v1_blkio"] = config.CapabilityInfo{Available: true, Detail: "cgroup v1 blkio controller present"}
		} else {
			result.Capabilities["cgroup_v1_blkio"] = config.CapabilityInfo{Available: false, Detail: blkioErr.Error()}
		}
	} else {
		result.Capabilities["cgroup_v1"] = config.CapabilityInfo{Available: false, Detail: err.Error()}
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

	// Landlock ABI v5+ features (IOCTL device control, Linux 6.10+)
	if data, err := os.ReadFile("/sys/kernel/security/landlock/abi"); err == nil {
		abi := strings.TrimSpace(string(data))
		if abiVer, convErr := strconv.Atoi(abi); convErr == nil {
			if abiVer >= 5 {
				result.Capabilities["landlock_ioctl"] = config.CapabilityInfo{Available: true, Detail: "IOCTL device control (ABI v5+)"}
			} else {
				result.Capabilities["landlock_ioctl"] = config.CapabilityInfo{Available: false, Detail: fmt.Sprintf("requires ABI v5, current: v%d", abiVer)}
			}
			if abiVer >= 6 {
				result.Capabilities["landlock_scoped"] = config.CapabilityInfo{Available: true, Detail: "IPC scoped rules (ABI v6+)"}
			} else {
				result.Capabilities["landlock_scoped"] = config.CapabilityInfo{Available: false, Detail: fmt.Sprintf("requires ABI v6, current: v%d", abiVer)}
			}
		}
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
	hasCGv1 := result.Capabilities["cgroup_v1"].Available
	hasLandlock := result.Capabilities["landlock"].Available
	hasSeccomp := result.Capabilities["seccomp"].Available
	hasTmpfs := result.Capabilities["tmpfs"].Available
	hasPivotRoot := result.Capabilities["pivot_root"].Available

	fullIsolation := hasUnshare && hasUserNS && hasMountNS && hasPidNS && hasNetNS && hasTmpfs && hasPivotRoot
	reducedIsolation := hasSeccomp && hasLandlock

	result.Features["network_isolation"] = fullIsolation
	result.Features["file_read_restriction"] = fullIsolation || reducedIsolation
	result.Features["file_write_restriction"] = fullIsolation || reducedIsolation
	result.Features["memory_limit"] = (hasCGv2 && result.Capabilities["cgroup_v2_memory"].Available) || hasCGv1
	result.Features["cpu_limit"] = (hasCGv2 && result.Capabilities["cgroup_v2_cpu"].Available) || (hasCGv1 && result.Capabilities["cgroup_v1_cpu"].Available)
	result.Features["process_limit"] = (hasCGv2 && result.Capabilities["cgroup_v2_pids"].Available) || (hasCGv1 && result.Capabilities["cgroup_v1_pids"].Available)
	result.Features["io_limit"] = (hasCGv2 && result.Capabilities["cgroup_v2_io"].Available) || (hasCGv1 && result.Capabilities["cgroup_v1_blkio"].Available)
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
	result.Features["dev_setup"] = fullIsolation || reducedIsolation
	result.Features["die_with_parent"] = true
	result.Features["new_session"] = true
	result.Features["tmp_overlay"] = fullIsolation
	result.Features["file_locks"] = true
	result.Features["json_status"] = true
	result.Features["bind_use_fd"] = fullIsolation
	result.Features["seccomp_stacking"] = hasSeccomp
	result.Features["pid_reaper"] = fullIsolation
	result.Features["mount_propagation_control"] = fullIsolation
	result.Features["submount_readonly_enforcement"] = fullIsolation
	result.Features["proc_hardening"] = fullIsolation
	result.Features["extra_fd_cleanup"] = true
	result.Features["landlock_ioctl_control"] = result.Capabilities["landlock_ioctl"].Available
	result.Features["landlock_scoped_rules"] = result.Capabilities["landlock_scoped"].Available
	result.Features["protect_system"] = true
	result.Features["protect_home"] = fullIsolation
	result.Features["private_tmp"] = fullIsolation
	result.Features["cross_ns_fd_binding"] = fullIsolation
	result.Features["exclusive_file_locks"] = true
	result.Features["map_to_target_uid"] = hasUserNS
	result.Features["kafel_seccomp_policy"] = hasSeccomp
	result.Features["cgroup_v1_fallback"] = result.Capabilities["cgroup_v1"].Available

	return result
}
