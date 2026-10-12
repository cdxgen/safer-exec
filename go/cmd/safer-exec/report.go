package main

// The report channel carries the engine's results to the Node runner: audit
// entries and the structured results (FSDIFF, LEARNED, CRYPTO, DRYRUN,
// PROFILE). The workload writes to the same stdout and stderr as the engine,
// so anything parsed from those streams can be forged; the report channel is
// a separate pipe (cfg.ReportFd) that the workload never inherits. Without it
// (an engine run by hand or from a test) audit lines go to stderr and
// structured results to stdout, as before.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

var (
	reportMu  sync.Mutex
	reportOut *os.File
)

// openReport attaches the report channel the runner passed as fd.
func openReport(fd int) error {
	if fd <= 0 {
		return nil
	}
	f, err := reportFile(fd)
	if err != nil {
		return err
	}
	reportOut = f
	// The first line tells the runner the channel is live; without it the
	// runner knows it is talking to an engine that predates the channel.
	reportLine(struct {
		Report int `json:"report"`
	}{1})
	return nil
}

// reportActive reports whether results go over the report channel.
func reportActive() bool {
	return reportOut != nil
}

func reportLine(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	reportMu.Lock()
	defer reportMu.Unlock()
	_, _ = reportOut.Write(append(data, '\n'))
}

// emitAuditLine sends one audit entry, a JSON object, over the report channel
// when there is one and to fallback (normally stderr) otherwise.
func emitAuditLine(entry []byte, fallback io.Writer) {
	if reportOut == nil {
		line := make([]byte, 0, len(entry)+1)
		_, _ = fallback.Write(append(append(line, entry...), '\n'))
		return
	}
	if !json.Valid(entry) {
		return
	}
	reportLine(struct {
		Audit json.RawMessage `json:"audit"`
	}{entry})
}

// reportStructured sends a structured result over the report channel and
// reports whether it did. PROFILE is text; every other result is JSON.
func reportStructured(marker string, data []byte) bool {
	if reportOut == nil {
		return false
	}
	name := strings.TrimSuffix(marker, ":")
	payload := json.RawMessage(data)
	if name == "PROFILE" || !json.Valid(data) {
		payload, _ = json.Marshal(string(data))
	}
	reportLine(struct {
		Result string          `json:"result"`
		Data   json.RawMessage `json:"data"`
	}{name, payload})
	return true
}

// writeStructured writes a structured result ("FSDIFF:" and its JSON):
// over the report channel when there is one, else to the file at
// cfg.StructuredOutputPath, else to stdout.
func writeStructured(cfg config.ExecConfig, marker string, data []byte) {
	if reportStructured(marker, data) {
		return
	}
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

// reportOpenError explains a report channel the runner asked for but the
// engine could not use; the run must not go ahead without it, or its results
// would silently be lost.
func reportOpenError(err error) error {
	return fmt.Errorf("report channel: %w", err)
}
