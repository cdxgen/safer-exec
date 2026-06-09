// Package main is the entrypoint for the safer-exec Go binary.
// It reads a JSON ExecConfig from stdin and delegates to the
// platform-specific engine (darwin or linux) to execute the
// sandboxed command.
//
// Usage:
//
//	echo '{"cmd":"npm","args":["install"],...}' | safer-exec
//
// Re-exec modes (Linux only):
//
//	safer-exec --init
//
//	When --init is passed, the binary skips stdin parsing and
//	re-reads config from SAFER_EXEC_CONFIG to set up namespaces
//	and execute the target command inside the new namespace.
//
//	safer-exec --init-reduced
//
//	Reduced isolation fallback used when user namespaces are
//	unavailable. Applies seccomp-bpf and Landlock only; skips
//	filesystem, PID, and network namespace isolation.
//
// Output modes:
//
//	When EnableDiff is true, the binary writes an fsDiff JSON report
//	to stdout after execution (prefixed with "FSDIFF:" marker).
//
//	When EnableLearn is true, the binary writes a learnedPolicy JSON
//	report to stdout after execution (prefixed with "LEARNED:" marker).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("sandboxed process exited with code %d", e.Code)
}

func init() {
	// Handle the re-exec patterns for Linux sandboxing.
	// We intercept in init() so it works even when running under `go test`
	// (where the test binary's generated main would otherwise call flag.Parse()
	// and fail on "--init" / "--init-reduced").
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--init":
			initMain()
			os.Exit(0)
		case "--init-reduced":
			initReducedMain()
			os.Exit(0)
		}
	}
}

func main() {
	// Handle Linux re-exec patterns for namespace setup
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--init":
			initMain()
			return
		case "--init-reduced":
			initReducedMain()
			return
		}
	}

	// Handle version flag
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("safer-exec 0.8.1")
		return
	}

	// Parse configuration from stdin
	cfg, err := readConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: invalid config: %v\n", err)
		os.Exit(1)
	}

	// Detect and warn about sensitive environment variables prior to execution
	checkSensitiveEnv(cfg.Env)

	// Delegate to the platform-specific engine
	runErr := run(cfg)
	if runErr != nil {
		if exitErr, ok := runErr.(*ExitError); ok {
			os.Exit(exitErr.Code)
		}
		fmt.Fprintf(os.Stderr, "safer-exec: %v\n", runErr)
		os.Exit(1)
	}
}

// checkSensitiveEnv scans the environment variables map for keys containing
// sensitive suffixes/substrings case-insensitively and prints a consolidated warning to Stderr.
func checkSensitiveEnv(env map[string]string) {
	if len(env) == 0 {
		return
	}
	var detected []string
	patterns := []string{"TOKEN", "PASSWORD", "SECRET", "API_KEY", "CLIENT_SECRET", "SESSION", "COOKIE", "AUTH", "KEY"}
	for k := range env {
		uk := strings.ToUpper(k)
		for _, p := range patterns {
			if strings.Contains(uk, p) {
				detected = append(detected, k)
				break
			}
		}
	}
	if len(detected) > 0 {
		sort.Strings(detected)
		fmt.Fprintf(os.Stderr, "safer-exec: warning: sensitive environment variables detected: %s\n", strings.Join(detected, ", "))
	}
}

// readConfig parses the JSON ExecConfig from stdin.
// It validates required fields and returns a populated config struct.
func readConfig() (config.ExecConfig, error) {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return config.ExecConfig{}, fmt.Errorf("reading stdin: %w", err)
	}

	if len(raw) == 0 {
		return config.ExecConfig{}, fmt.Errorf("empty config provided")
	}

	var cfg config.ExecConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return config.ExecConfig{}, fmt.Errorf("parsing JSON: %w", err)
	}

	// Validate required fields
	if cfg.Cmd == "" {
		return config.ExecConfig{}, fmt.Errorf("cmd is required")
	}

	return cfg, nil
}

// initMain is called when the binary re-executes itself with --init.
// It reads config from the SAFER_EXEC_CONFIG environment variable,
// sets up namespaces, and executes the target command.
func initMain() {
	cfgJSON := os.Getenv("SAFER_EXEC_CONFIG")
	if cfgJSON == "" {
		fmt.Fprintln(os.Stderr, "safer-exec: SAFER_EXEC_CONFIG not set")
		os.Exit(1)
	}

	var cfg config.ExecConfig
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: init config parse: %v\n", err)
		os.Exit(1)
	}

	if err := runInit(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: init: %v\n", err)
		os.Exit(1)
	}
}

// initReducedMain is called when the binary re-executes itself with --init-reduced.
// It applies only seccomp-bpf and Landlock (no namespace or filesystem isolation)
// and executes the target command directly.
func initReducedMain() {
	cfgJSON := os.Getenv("SAFER_EXEC_CONFIG")
	if cfgJSON == "" {
		fmt.Fprintln(os.Stderr, "safer-exec: SAFER_EXEC_CONFIG not set")
		os.Exit(1)
	}

	var cfg config.ExecConfig
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: init-reduced config parse: %v\n", err)
		os.Exit(1)
	}

	if err := runInitReduced(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: init-reduced: %v\n", err)
		os.Exit(1)
	}
}
