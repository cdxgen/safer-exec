// Package learner provides behavioral auto-profiling (learning mode).
// It runs a command in permissive mode and records all filesystem and
// network accesses, then generates a strict policy from the observations.
//
// On Linux it uses strace (if available) or /proc-based tracing.
// On macOS it uses Seatbelt trace rules and parses the output.
package learner

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// Learner tracks filesystem and network behavior during command execution.
type Learner struct {
	readPaths   map[string]bool
	writePaths  map[string]bool
	allowIPs    map[string]bool
	allowHosts  map[string]bool
	allowPorts  map[int]bool
	allowListen map[string]bool
	envVars     map[string]bool
}

// New creates a new Learner.
func New() *Learner {
	return &Learner{
		readPaths:   make(map[string]bool),
		writePaths:  make(map[string]bool),
		allowIPs:    make(map[string]bool),
		allowHosts:  make(map[string]bool),
		allowPorts:  make(map[int]bool),
		allowListen: make(map[string]bool),
		envVars:     make(map[string]bool),
	}
}

// Learn runs the given command and returns a PolicyFile based on
// observed behavior. It uses strace on Linux and proc-based tracing as fallback.
//
// When cfg.PolicyFilePath is non-empty, the result is merged with the
// existing file on disk and written back atomically.
func (l *Learner) Learn(cfg config.ExecConfig) (*config.PolicyFile, error) {
	// Try strace first (Linux), fall back to proc-based tracing
	cmd, args := cfg.Cmd, cfg.Args

	// Build env securely using filtered environment
	env := config.BuildEnv(cfg.Env)

	// Try strace for comprehensive tracing
	if stracePath, err := exec.LookPath("strace"); err == nil {
		return l.learnWithStrace(cfg, stracePath, cmd, args, env, cfg.WorkingDir)
	}

	// Fall back to basic tracing (pre/post snapshot + network scan)
	return l.learnBasic(cfg, cmd, args, env, cfg.WorkingDir)
}

// learnWithStrace uses strace to capture all syscalls.
func (l *Learner) learnWithStrace(cfg config.ExecConfig, stracePath, cmd string, args, env []string, workDir string) (*config.PolicyFile, error) {
	// strace flags:
	// -e trace=openat,open,readlink,connect,recvfrom: trace file opens and network connects
	// -o: output to file
	// -w: show wait time (helpful for debugging)
	tmpFile, err := os.CreateTemp("", "safer-exec-strace-*.log")
	if err != nil {
		return nil, fmt.Errorf("create strace log: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	straceArgs := []string{
		"-f",
		"-e", "trace=openat,open,readlink,connect,bind,sendto,recvfrom,stat,stat64,fstat,fstat64,lstat,lstat64,access",
		"-o", tmpFile.Name(),
		cmd,
	}
	straceArgs = append(straceArgs, args...)

	c := exec.Command(stracePath, straceArgs...)
	c.Env = env
	if workDir != "" {
		c.Dir = workDir
	}
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	if err := c.Run(); err != nil {
		// Continue even if command fails — we still learn from what happened
	}

	// Parse strace output
	if err := l.parseStraceLog(tmpFile.Name()); err != nil {
		return nil, fmt.Errorf("parse strace log: %w", err)
	}

	policy := l.buildPolicy(cmd, args)
	return l.mergeAndWrite(cfg, policy), nil
}

// parseStraceLog parses the strace output file.
func (l *Learner) parseStraceLog(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open strace log: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		l.parseStraceLine(line)
	}

	return scanner.Err()
}

// parseStraceLine extracts filesystem and network info from a single strace line.
func (l *Learner) parseStraceLine(line string) {
	// strace output format:
	// openat(AT_FDCWD, "/path/to/file", O_RDONLY) = 3
	// connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0

	// Extract file paths
	if strings.Contains(line, "openat(") || strings.Contains(line, "open(") ||
		strings.Contains(line, "stat(") || strings.Contains(line, "access(") ||
		strings.Contains(line, "readlink(") {
		if paths := extractPaths(line); len(paths) > 0 {
			for _, p := range paths {
				// Determine read vs write from flags
				if strings.Contains(line, "O_WRONLY") || strings.Contains(line, "O_RDWR") ||
					strings.Contains(line, "O_CREAT") || strings.Contains(line, "O_TRUNC") {
					l.writePaths[p] = true
				} else {
					l.readPaths[p] = true
				}
			}
		}
	}

	// Extract network connections
	if strings.Contains(line, "connect(") {
		if ip := extractIP(line); ip != "" {
			l.allowIPs[ip] = true
		}
		if port := extractPort(line); port > 0 {
			l.allowPorts[port] = true
		}
	}

	// Extract network binds (listening)
	if strings.Contains(line, "bind(") {
		ip := extractIP(line)
		port := extractPort(line)
		if ip != "" {
			if port > 0 {
				l.allowListen[fmt.Sprintf("%s:%d", ip, port)] = true
			} else {
				l.allowListen[ip] = true
			}
		}
	}
}

// learnBasic falls back to pre/post snapshot comparison and network scanning.
func (l *Learner) learnBasic(cfg config.ExecConfig, cmd string, args, env []string, workDir string) (*config.PolicyFile, error) {
	// Capture pre-execution network state
	preConns := getNetworkConnections()

	// Run the command
	c := exec.Command(cmd, args...)
	c.Env = env
	if workDir != "" {
		c.Dir = workDir
	}
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	_ = c.Run()

	// Capture post-execution network state
	postConns := getNetworkConnections()

	// Find new connections
	for _, conn := range postConns {
		found := false
		for _, pre := range preConns {
			if conn.ip == pre.ip && conn.port == pre.port {
				found = true
				break
			}
		}
		if !found {
			l.allowIPs[conn.ip] = true
			l.allowPorts[conn.port] = true
		}
	}

	// Track environment variables used
	for _, e := range env {
		if idx := strings.IndexByte(e, '='); idx > 0 {
			l.envVars[e[:idx]] = true
		}
	}

	policy := l.buildPolicy(cmd, args)
	return l.mergeAndWrite(cfg, policy), nil
}

// mergeAndWrite merges the observed policy with an existing file on disk
// when cfg.PolicyFilePath is set, and writes the merged result back atomically.
// Returns the (possibly merged) policy.
func (l *Learner) mergeAndWrite(cfg config.ExecConfig, observed *config.PolicyFile) *config.PolicyFile {
	if cfg.PolicyFilePath == "" {
		return observed
	}

	// Read existing policy file
	base, err := config.ReadPolicyFile(cfg.PolicyFilePath)
	if err != nil {
		// File doesn't exist yet or is unreadable — treat observed as the full policy
		if err := config.WritePolicyFile(cfg.PolicyFilePath, observed); err != nil {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: write policy file: %v\n", err)
		}
		return observed
	}

	// Merge observed into base
	merged := config.MergePolicies(base, observed)

	// Write merged policy back atomically
	if err := config.WritePolicyFile(cfg.PolicyFilePath, merged); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: warning: write merged policy file: %v\n", err)
	}

	return merged
}

// learnGroupDepth is the max directory segments to keep when grouping paths.
const learnGroupDepth = 4

// buildPolicy converts collected observations into a PolicyFile.
func (l *Learner) buildPolicy(cmd string, args []string) *config.PolicyFile {
	// Initialize all slices to empty arrays (not nil) so JSON serializes as [] not null
	policy := &config.PolicyFile{
		Cmd:         cmd,
		Args:        args,
		ReadPaths:   []string{},
		WritePaths:  []string{},
		AllowHosts:  []string{},
		AllowIPs:    []string{},
		AllowPorts:  []int{},
		AllowListen: []string{},
		EnvVars:     []string{},
	}

	// Deduplicate paths to their common parent directories
	policy.ReadPaths = l.dedupPaths(l.readPaths)
	if policy.ReadPaths == nil {
		policy.ReadPaths = []string{}
	}
	policy.WritePaths = l.dedupPaths(l.writePaths)
	if policy.WritePaths == nil {
		policy.WritePaths = []string{}
	}

	// IPs and hosts
	for ip := range l.allowIPs {
		policy.AllowIPs = append(policy.AllowIPs, ip)
	}
	sort.Strings(policy.AllowIPs)

	for host := range l.allowHosts {
		policy.AllowHosts = append(policy.AllowHosts, host)
	}
	sort.Strings(policy.AllowHosts)

	// Ports
	for port := range l.allowPorts {
		policy.AllowPorts = append(policy.AllowPorts, port)
	}
	sort.Ints(policy.AllowPorts)

	// Listen
	for item := range l.allowListen {
		policy.AllowListen = append(policy.AllowListen, item)
	}
	sort.Strings(policy.AllowListen)

	// Env vars
	for v := range l.envVars {
		policy.EnvVars = append(policy.EnvVars, v)
	}
	sort.Strings(policy.EnvVars)

	// Determine AllowCrypto based on observed reads
	hasCryptoRead := false
	hasFIPSRead := false
	hasGPURead := false
	hasTPMRead := false
	hasVMRead := false
	for p := range l.readPaths {
		up := strings.ToLower(p)
		if strings.Contains(up, "libcrypto") || strings.Contains(up, "libssl") || strings.Contains(up, "/ssl") || strings.Contains(up, "security") {
			hasCryptoRead = true
		}
		if strings.Contains(up, "fips_enabled") || strings.Contains(up, "fips.so") || strings.Contains(up, "fips.dylib") {
			hasFIPSRead = true
		}
		if strings.Contains(up, "nvidia") || strings.Contains(up, "/dev/dri") || strings.Contains(up, "cuda") {
			hasGPURead = true
		}
		if strings.Contains(up, "/dev/tpm") {
			hasTPMRead = true
		}
		if strings.Contains(up, "dmi/id") || strings.Contains(up, "hypervisor") {
			hasVMRead = true
		}
	}

	// Control directives: only enable when the feature was actually observed.
	policy.AllowCrypto = hasCryptoRead
	policy.FIPSDetected = hasFIPSRead

	policy.AllowGPU = hasGPURead
	policy.BlockTPM = hasTPMRead
	policy.SpoofAntiVM = hasVMRead

	// Informational: record what was detected
	policy.GPUUsed = hasGPURead
	policy.TPMUsed = hasTPMRead
	policy.AntiVMActive = hasVMRead

	return policy
}

// dedupPaths groups paths by truncating each to learnGroupDepth segments
// then deduplicating the results.
func (l *Learner) dedupPaths(paths map[string]bool) []string {
	seen := make(map[string]bool, len(paths))
	for p := range paths {
		grouped := truncatePathDepth(p, learnGroupDepth)
		seen[grouped] = true
	}

	result := make([]string, 0, len(seen))
	for p := range seen {
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.Count(result[i], string(filepath.Separator)) <
			strings.Count(result[j], string(filepath.Separator))
	})
	return result
}

// truncatePathDepth truncates an absolute path to at most maxDepth segments.
func truncatePathDepth(path string, maxDepth int) string {
	parts := strings.Split(path, string(filepath.Separator))
	if len(parts) <= maxDepth {
		return path
	}
	truncated := strings.Join(parts[:maxDepth], string(filepath.Separator))
	if truncated == "" {
		return string(filepath.Separator)
	}
	return truncated
}

// --- Helper functions ---

func extractPaths(line string) []string {
	var paths []string
	// Find quoted strings
	for i := 0; i < len(line)-1; i++ {
		if line[i] == '"' {
			j := i + 1
			for j < len(line) && line[j] != '"' {
				j++
			}
			path := line[i+1 : j]
			if strings.HasPrefix(path, "/") || strings.HasPrefix(path, ".") {
				paths = append(paths, path)
			}
			i = j
		}
	}
	return paths
}

func extractIP(line string) string {
	// Look for inet_addr("X.X.X.X") or sin_addr patterns
	idx := strings.Index(line, "inet_addr(")
	if idx == -1 {
		idx = strings.Index(line, "sin_addr=")
	}
	if idx == -1 {
		return ""
	}
	rest := line[idx:]
	// Find the IP address
	for i := 0; i < len(rest); i++ {
		if rest[i] == '"' || rest[i] == '(' {
			j := i + 1
			for j < len(rest) && rest[j] != '"' && rest[j] != ')' {
				j++
			}
			ip := rest[i+1 : j]
			if isValidIP(ip) {
				return ip
			}
		}
	}
	return ""
}

func extractPort(line string) int {
	// Look for htons(N) or sin_port=htons(N)
	idx := strings.Index(line, "htons(")
	if idx == -1 {
		return 0
	}
	rest := line[idx+6:]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j > 0 {
		port, _ := strconv.Atoi(rest[:j])
		return port
	}
	return 0
}

func isValidIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

type connInfo struct {
	ip   string
	port int
}

func getNetworkConnections() []connInfo {
	var conns []connInfo

	// Read /proc/net/tcp and /proc/net/tcp6
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		scanner.Scan() // skip header
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			parts := strings.Fields(line)
			if len(parts) < 4 {
				continue
			}

			// Parse local address:port (hex format)
			local := strings.Split(parts[1], ":")
			if len(local) != 2 {
				continue
			}

			port, _ := strconv.ParseInt(local[1], 16, 32)
			_ = port // local port (not needed for egress tracking)

			// Parse remote address:port
			remote := strings.Split(parts[2], ":")
			if len(remote) != 2 {
				continue
			}

			ip := hexToIP(remote[0])
			rport, _ := strconv.ParseInt(remote[1], 16, 32)

			conns = append(conns, connInfo{
				ip:   ip,
				port: int(rport),
			})
		}
	}

	return conns
}

func hexToIP(hex string) string {
	if len(hex) == 8 {
		// IPv4 in little-endian hex
		a, _ := strconv.ParseInt(hex[6:8], 16, 32)
		b, _ := strconv.ParseInt(hex[4:6], 16, 32)
		c, _ := strconv.ParseInt(hex[2:4], 16, 32)
		d, _ := strconv.ParseInt(hex[0:2], 16, 32)
		return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
	}
	if len(hex) == 32 {
		return hex // IPv6 raw hex
	}
	return hex
}
