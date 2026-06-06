// Package main is the entrypoint for the safer-exec Go binary.
// It reads a JSON ExecConfig from stdin and delegates to the
// platform-specific engine (darwin or linux) to execute the
// sandboxed command.
//
// Usage:
//
//	echo '{"cmd":"npm","args":["install"],...}' | safer-exec
//
// Re-exec mode (Linux only):
//
//	safer-exec --init
//
//	When --init is passed, the binary skips stdin parsing and
//	re-reads config from an environment variable to set up
//	namespaces in the child process.
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

	"github.com/cdxgen/safer-exec/go/internal/config"
)

type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("sandboxed process exited with code %d", e.Code)
}

func init() {
	// Handle the re-exec pattern for Linux sandboxing.
	// When the binary re-executes itself with --init, it must act as the
	// sandbox init process. We intercept this in init() so it works even
	// when running under `go test` (where the test binary's generated main
	// function would otherwise call flag.Parse() and fail on "--init").
	if len(os.Args) > 1 && os.Args[1] == "--init" {
		initMain()
		os.Exit(0)
	}
}

func main() {
	// Handle Linux re-exec pattern for namespace setup
	if len(os.Args) > 1 && os.Args[1] == "--init" {
		initMain()
		return
	}

	// Handle version flag
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("safer-exec 0.1.0")
		return
	}

	// Parse configuration from stdin
	cfg, err := readConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: invalid config: %v\n", err)
		os.Exit(1)
	}

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
