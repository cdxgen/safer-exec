// Package learnermac provides macOS-specific learning mode via Seatbelt trace parsing.
//
// macOS Seatbelt (trace ...) rules log all resource accesses to a trace file.
// We parse that trace file to extract filesystem reads, writes, and network connections.
package learnermac

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// TraceParser parses Seatbelt trace output files.
type TraceParser struct {
	readPaths  map[string]bool
	writePaths map[string]bool
	allowIPs   map[string]bool
	allowPorts map[int]bool
}

// NewTraceParser creates a new trace parser.
func NewTraceParser() *TraceParser {
	return &TraceParser{
		readPaths:  make(map[string]bool),
		writePaths: make(map[string]bool),
		allowIPs:   make(map[string]bool),
		allowPorts: make(map[int]bool),
	}
}

// ParseTraceFile parses a Seatbelt trace log file and populates the parser's state.
//
// Seatbelt trace output format:
//
//	sandbox: process 12345 (sh): file-read "/usr/lib/libSystem.B.dylib"
//	sandbox: process 12345 (sh): file-write "/tmp/output.txt"
//	sandbox: process 12345 (sh): network-outbound to "93.184.216.34:443"
func (p *TraceParser) ParseTraceFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open trace file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		p.parseLine(line)
	}

	return scanner.Err()
}

// parseLine extracts resource access info from a single trace line.
func (p *TraceParser) parseLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}

	// File read
	if strings.Contains(line, "file-read") {
		if path := extractPath(line); path != "" {
			p.readPaths[path] = true
		}
	}

	// File write
	if strings.Contains(line, "file-write") {
		if path := extractPath(line); path != "" {
			p.writePaths[path] = true
		}
	}

	// Network outbound
	if strings.Contains(line, "network-outbound") {
		if ip, port := extractNetworkTarget(line); ip != "" {
			p.allowIPs[ip] = true
			if port > 0 {
				p.allowPorts[port] = true
			}
		}
	}
}

// BuildPolicy converts the parsed trace into a LearnedPolicy.
func (p *TraceParser) BuildPolicy(cmd string, args []string) *config.LearnedPolicy {
	// Initialize all slices to empty arrays (not nil) so JSON serializes as [] not null
	policy := &config.LearnedPolicy{
		Cmd:        cmd,
		Args:       args,
		ReadPaths:  []string{},
		WritePaths: []string{},
		AllowHosts: []string{},
		AllowIPs:   []string{},
		AllowPorts: []int{},
		EnvVars:    []string{},
	}

	// Deduplicate paths
	policy.ReadPaths = dedupPaths(p.readPaths)
	if policy.ReadPaths == nil {
		policy.ReadPaths = []string{}
	}
	policy.WritePaths = dedupPaths(p.writePaths)
	if policy.WritePaths == nil {
		policy.WritePaths = []string{}
	}

	// IPs
	for ip := range p.allowIPs {
		policy.AllowIPs = append(policy.AllowIPs, ip)
	}
	sort.Strings(policy.AllowIPs)

	// Ports
	for port := range p.allowPorts {
		policy.AllowPorts = append(policy.AllowPorts, port)
	}
	sort.Ints(policy.AllowPorts)

	return policy
}

// extractPath finds the file path in a trace line.
func extractPath(line string) string {
	// Find the last quoted string
	lastQuote := -1
	for i := len(line) - 1; i >= 0; i-- {
		if line[i] == '"' {
			lastQuote = i
			break
		}
	}
	if lastQuote == 0 {
		return ""
	}
	start := lastQuote - 1
	for start >= 0 && line[start] != '"' {
		start--
	}
	if start < 0 {
		return ""
	}
	return line[start+1 : lastQuote]
}

// extractNetworkTarget parses IP:port from network-outbound trace line.
func extractNetworkTarget(line string) (string, int) {
	// Look for "IP:PORT" pattern after "to"
	idx := strings.Index(line, "to \"")
	if idx == -1 {
		idx = strings.Index(line, "to '")
	}
	if idx == -1 {
		return "", 0
	}

	rest := line[idx+4:]
	end := strings.IndexAny(rest, "\"'")
	if end == -1 {
		return "", 0
	}

	target := rest[:end]
	parts := strings.Split(target, ":")
	if len(parts) == 2 {
		port, _ := strconv.Atoi(parts[1])
		return parts[0], port
	}
	if len(parts) == 1 {
		return parts[0], 0
	}
	return target, 0
}

// dedupPaths returns the minimal set of parent directories covering all paths.
func dedupPaths(paths map[string]bool) []string {
	pathList := make([]string, 0, len(paths))
	for p := range paths {
		pathList = append(pathList, p)
	}
	sort.Strings(pathList)

	var result []string
	for _, p := range pathList {
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

	if result == nil {
		result = []string{}
	}

	return result
}
