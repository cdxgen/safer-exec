package mxc

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// DenialReport is the actionable report MXC writes for captureDenials: one
// entry per distinct (resource, accessType) the policy did not grant.
type DenialReport struct {
	Denials []Denial      `json:"denials"`
	Summary DenialSummary `json:"summary"`
}

// Denial is one denied (or, in permissive mode, allowed-and-recorded) access.
type Denial struct {
	// Resource is an absolute path for files, a capability name for
	// capabilities and the raw identifier otherwise.
	Resource string `json:"resource"`
	// ResourceType is one of file, ui, network, capability, other.
	ResourceType string `json:"resourceType"`
	// AccessType is one of read, write, execute, unknown.
	AccessType string `json:"accessType"`
	PID        uint32 `json:"pid"`
	Filetime   string `json:"filetime"`
}

// DenialSummary is the report summary.
type DenialSummary struct {
	ExitCode                 int64 `json:"exitCode"`
	TotalDenials             int   `json:"totalDenials"`
	DeniedResourcesTruncated bool  `json:"deniedResourcesTruncated"`
}

// ReadDenialReport parses a denial report file.
func ReadDenialReport(path string) (*DenialReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r DenialReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse denial report %s: %w", path, err)
	}
	return &r, nil
}

// VerboseSibling returns the path of the redacted verbose report MXC writes
// next to an actionable report ("denials.<id>.json" ->
// "denials.<id>.verbose.json").
func VerboseSibling(path string) string {
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		return path[:len(path)-len(".json")] + ".verbose.json"
	}
	return path + ".verbose.json"
}

// IsBaselineNoise reports whether a denial is one every console process
// produces while starting inside a BaseContainer, independent of what the
// workload does: a write-intent open of %SystemRoot% itself, a read of the
// per-user console settings key, and the Win32k GUI conversion that the UI
// lockdown refuses. Reporting them on every run would only bury real
// findings.
func IsBaselineNoise(d Denial, systemRoot string) bool {
	switch d.ResourceType {
	case "ui":
		return d.Resource == "ConvertToGui"
	case "other":
		r := strings.ToUpper(d.Resource)
		return strings.HasPrefix(r, `\REGISTRY\USER\`) && strings.HasSuffix(r, `\CONSOLE`)
	case "file":
		return d.AccessType == "write" && systemRoot != "" && WinIsAbs(d.Resource) && WinEqual(d.Resource, systemRoot)
	}
	return false
}

// WithoutBaseline returns a copy of the report without baseline noise.
func (r *DenialReport) WithoutBaseline(systemRoot string) *DenialReport {
	if r == nil {
		return nil
	}
	out := &DenialReport{Summary: r.Summary}
	for _, d := range r.Denials {
		if !IsBaselineNoise(d, systemRoot) {
			out.Denials = append(out.Denials, d)
		}
	}
	out.Summary.TotalDenials = len(out.Denials)
	return out
}

// auditType maps a denial onto safer-exec's audit/dry-run vocabulary.
func auditType(d Denial) string {
	switch d.ResourceType {
	case "file":
		switch d.AccessType {
		case "read":
			return "file-read"
		case "write":
			return "file-write"
		case "execute":
			return "process-exec"
		default:
			return "file-access"
		}
	case "network":
		return "network-outbound"
	case "capability":
		return "capability"
	case "ui":
		return "ui"
	default:
		return "other"
	}
}

// AuditEntries converts the report into safer-exec audit entries.
func (r *DenialReport) AuditEntries() []config.AuditEntry {
	if r == nil {
		return nil
	}
	out := make([]config.AuditEntry, 0, len(r.Denials))
	for _, d := range r.Denials {
		if d.Resource == "" {
			continue
		}
		detail := fmt.Sprintf("violation detected at %s", d.Resource)
		if d.ResourceType == "capability" {
			detail = fmt.Sprintf("container capability %s was not granted", d.Resource)
		}
		out = append(out, config.AuditEntry{Type: auditType(d), Target: d.Resource, Detail: detail})
	}
	return out
}

// DryRunEvents converts the report into dry-run events.
func (r *DenialReport) DryRunEvents() []config.DryRunEvent {
	if r == nil {
		return nil
	}
	out := make([]config.DryRunEvent, 0, len(r.Denials))
	for _, d := range r.Denials {
		if d.Resource == "" {
			continue
		}
		ev := config.DryRunEvent{Type: auditType(d)}
		switch d.ResourceType {
		case "file":
			ev.Path = d.Resource
		case "network":
			host, port := splitHostPort(d.Resource)
			ev.Target, ev.Port = host, port
		default:
			ev.Target = d.Resource
		}
		out = append(out, ev)
	}
	return out
}

func splitHostPort(s string) (string, int) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return s, 0
	}
	port, _ := strconv.Atoi(p)
	return h, port
}

// containerProfileMarker identifies paths inside the per-run container
// profile (its private TEMP/LOCALAPPDATA), which never belong in a policy.
const containerProfileMarker = `\packages\sandbox.{`

// LearnInput carries what a learning run observed.
type LearnInput struct {
	Cmd  string
	Args []string
	// Report is the permissive-mode denial report (accesses outside the
	// policy that were allowed and recorded).
	Report *DenialReport
	// Plan is the plan the learning run executed; its grants were in effect
	// and therefore never appear in Report.
	Plan *Plan
	// ProxyTargets are "host:port" egress targets the learning proxy saw.
	ProxyTargets []string
	// NetworkDisabled reports whether the learning run had no network.
	NetworkDisabled bool
}

// LearnPolicy builds a policy from a learning run: the grants the run already
// had plus every recorded access, collapsed to minimal path sets, and the
// hostnames and ports the egress proxy observed.
func LearnPolicy(in LearnInput) *config.PolicyFile {
	policy := &config.PolicyFile{
		Cmd:        in.Cmd,
		Args:       in.Args,
		ReadPaths:  []string{},
		WritePaths: []string{},
		AllowHosts: []string{},
		AllowIPs:   []string{},
		AllowPorts: []int{},
	}
	var reads, writes, anchors, pathDirs []string
	systemRoot := ""
	if in.Plan != nil {
		reads = append(reads, in.Plan.ReadPaths...)
		writes = append(writes, in.Plan.WritePaths...)
		anchors = append(anchors, in.Plan.Cwd, WinDir(in.Plan.Program))
		systemRoot = in.Plan.SystemRoot
		env := ParseEnviron(in.Plan.Request.Process.Env)
		if pathList, ok := env.Get("PATH"); ok {
			for dir := range strings.SplitSeq(pathList, ";") {
				if dir = strings.Trim(strings.TrimSpace(dir), `"`); WinIsAbs(dir) {
					pathDirs = append(pathDirs, WinClean(dir))
				}
			}
		}
	}
	anchors = append(anchors, reads...)
	anchors = append(anchors, writes...)

	type observed struct {
		path  string
		dir   bool
		write bool
	}
	var seen []observed
	if in.Report != nil {
		for _, d := range in.Report.Denials {
			if d.ResourceType != "file" || !WinIsAbs(d.Resource) || IsBaselineNoise(d, systemRoot) {
				continue
			}
			path := WinClean(d.Resource)
			switch {
			case strings.Contains(strings.ToLower(path), containerProfileMarker):
				// The container's private profile (TEMP, LOCALAPPDATA).
				continue
			case WinIsVolumeRoot(path):
				// Volume-root grants do not cascade and are never needed.
				continue
			case systemRoot != "" && WinHasPrefix(path, systemRoot):
				// The Windows directory is readable without a grant and must
				// never be granted for writing.
				continue
			}
			seen = append(seen, observed{
				path:  path,
				dir:   strings.HasSuffix(d.Resource, `\`) || strings.HasSuffix(d.Resource, "/"),
				write: d.AccessType == "write",
			})
		}
	}
	for _, o := range seen {
		if o.write {
			writes = append(writes, o.path)
			anchors = append(anchors, o.path)
		} else if !o.dir {
			anchors = append(anchors, o.path)
		}
	}
	for _, o := range seen {
		if o.write || !o.dir {
			if !o.write {
				reads = append(reads, o.path)
			}
			continue
		}
		// A read of a directory is learned only when it is not path-resolution
		// noise: opening the ancestors of a working path, or a shell probing
		// each PATH entry for a command, would otherwise turn into recursive
		// grants over whole profile trees.
		if isAncestorOfAny(o.path, anchors) || containsPath(pathDirs, o.path) {
			continue
		}
		reads = append(reads, o.path)
	}
	policy.WritePaths = collapsePaths(writes, nil)
	policy.ReadPaths = collapsePaths(reads, policy.WritePaths)

	if in.NetworkDisabled {
		policy.DisableNetwork = true
		return policy
	}
	hosts := map[string]bool{}
	ips := map[string]bool{}
	ports := map[int]bool{}
	for _, t := range in.ProxyTargets {
		h, port := splitHostPort(t)
		if h == "" || port <= 0 || port > 65535 {
			// The proxy records host:port authorities only.
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ips[ip.String()] = true
		} else {
			hosts[strings.ToLower(h)] = true
		}
		if port > 0 {
			ports[port] = true
		}
	}
	for h := range hosts {
		policy.AllowHosts = append(policy.AllowHosts, h)
	}
	for ip := range ips {
		policy.AllowIPs = append(policy.AllowIPs, ip)
	}
	for port := range ports {
		policy.AllowPorts = append(policy.AllowPorts, port)
	}
	sort.Strings(policy.AllowHosts)
	sort.Strings(policy.AllowIPs)
	sort.Ints(policy.AllowPorts)
	if len(hosts) > 0 || len(ips) > 0 {
		// Hostnames are enforced at CONNECT time only through the proxy.
		policy.ProxyEgress = true
	}
	return policy
}

// isAncestorOfAny reports whether dir is a strict ancestor of any path.
func isAncestorOfAny(dir string, paths []string) bool {
	for _, p := range paths {
		if p != "" && !WinEqual(p, dir) && WinHasPrefix(p, dir) {
			return true
		}
	}
	return false
}

// collapsePaths de-duplicates paths case-insensitively and drops every path
// already covered by another entry or by one of the cover paths.
func collapsePaths(paths, cover []string) []string {
	clean := make([]string, 0, len(paths))
	for _, p := range paths {
		if WinIsAbs(p) {
			clean = append(clean, WinClean(p))
		}
	}
	sort.Slice(clean, func(i, j int) bool {
		if len(clean[i]) != len(clean[j]) {
			return len(clean[i]) < len(clean[j])
		}
		return strings.ToLower(clean[i]) < strings.ToLower(clean[j])
	})
	out := []string{}
	for _, p := range clean {
		if coveredBy(p, out) || coveredBy(p, cover) {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}
