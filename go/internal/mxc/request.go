// Package mxc translates the safer-exec ExecConfig contract into Microsoft
// eXecution Container (MXC) create-and-run requests and interprets what the
// MXC Windows executor (wxc-exec.exe) reports back.
//
// The Windows engine drives MXC's ProcessContainer backend, which on current
// Windows 11 builds runs the workload in an OS "BaseContainer" created through
// CreateProcessSecurityEnvironment: a deny-by-default filesystem view, a
// per-container WFP egress policy, and per-container WinHTTP proxy settings.
//
// Everything in this package is host-independent: paths follow Windows rules
// regardless of the build host, and host facts (environment, file existence,
// DNS) are injected through Host, so the translation is unit-tested on every
// platform. Only the engine itself (cmd/safer-exec/engine_windows.go) and the
// job-object helpers are Windows-only.
package mxc

import (
	"encoding/json"
)

// SchemaVersion is the MXC request contract this package emits. MXC accepts
// only exact, registered version strings; 1.0.0 is the first stable contract
// and is immutable once published.
const SchemaVersion = "1.0.0"

// Containment is the MXC backend the Windows engine requests. It is spelled
// concretely rather than through the "process" intent so a future change of
// the intent's resolution can never silently select a different backend.
const Containment = "processcontainer"

// Network action values.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

// Capture-denials modes.
const (
	// CaptureBlock records accesses the policy does not grant while still
	// denying them (deny-and-record): enforcement is unchanged.
	CaptureBlock = "block"
	// CaptureAllow records accesses the policy does not grant and allows them
	// (permissive learning mode). It relaxes containment; safer-exec never
	// requests it (see Translate).
	CaptureAllow = "allow"
)

// Request is an MXC 1.0.0 one-shot (create-and-run) request. Only the fields
// the Windows engine uses are modelled; MXC rejects unknown fields, so the
// struct must stay a strict subset of the published schema.
type Request struct {
	Version          string            `json:"version"`
	Containment      string            `json:"containment"`
	Process          Process           `json:"process"`
	Filesystem       *Filesystem       `json:"filesystem,omitempty"`
	Network          *Network          `json:"network,omitempty"`
	RuntimeConfig    *RuntimeConfig    `json:"runtimeConfig,omitempty"`
	UI               *UI               `json:"ui,omitempty"`
	Telemetry        *Telemetry        `json:"telemetry,omitempty"`
	Fallback         *Fallback         `json:"fallback,omitempty"`
	ProcessContainer *ProcessContainer `json:"processContainer,omitempty"`
}

// Process describes the workload. Env is always supplied (never omitted) so
// the workload never receives MXC's default environment, which is the
// launching user's full profile environment.
type Process struct {
	CommandLine       string   `json:"commandLine"`
	Cwd               string   `json:"cwd,omitempty"`
	Env               []string `json:"env"`
	InheritDefaultEnv bool     `json:"inheritDefaultEnv"`
	Timeout           uint32   `json:"timeout,omitempty"`
}

// Filesystem is MXC's shared path policy. For the same object the strictest
// grant wins (denied > read-only > read-write) and a more specific path wins
// over its parent.
type Filesystem struct {
	ReadwritePaths []string `json:"readwritePaths,omitempty"`
	ReadonlyPaths  []string `json:"readonlyPaths,omitempty"`
	DeniedPaths    []string `json:"deniedPaths,omitempty"`
}

// Network is MXC's directional network policy.
type Network struct {
	Egress  Egress  `json:"egress"`
	Ingress Ingress `json:"ingress"`
}

// Egress is the outbound policy. Deny rules take precedence over allow rules.
type Egress struct {
	Default string `json:"default"`
	Allow   []Rule `json:"allow,omitempty"`
	Deny    []Rule `json:"deny,omitempty"`
}

// Rule matches destinations and ports. An omitted list matches everything in
// that dimension.
type Rule struct {
	To    []Peer `json:"to,omitempty"`
	Ports []Port `json:"ports,omitempty"`
}

// Peer is a CIDR destination.
type Peer struct {
	CIDR string `json:"cidr"`
}

// Port selects a transport protocol and destination port.
type Port struct {
	Protocol string `json:"protocol,omitempty"`
	Port     int    `json:"port,omitempty"`
	EndPort  int    `json:"endPort,omitempty"`
}

// Ingress controls private-network inbound traffic and bidirectional
// host-loopback connectivity. On ProcessContainer "default: allow" grants the
// bidirectional privateNetworkClientServer capability, which is also the
// prerequisite for reaching private-network destinations at all.
type Ingress struct {
	Default      string `json:"default"`
	HostLoopback string `json:"hostLoopback"`
}

// RuntimeConfig carries the caller-managed proxy endpoint.
type RuntimeConfig struct {
	NetworkProxy string `json:"networkProxy,omitempty"`
}

// UI is the cross-platform UI policy. The engine always states the full
// lockdown explicitly rather than relying on defaults.
type UI struct {
	Disable   bool   `json:"disable"`
	Clipboard string `json:"clipboard"`
	Injection bool   `json:"injection"`
}

// Telemetry is always disabled explicitly.
type Telemetry struct {
	Enabled bool `json:"enabled"`
}

// Fallback carries operator consent for host-mutating fallbacks.
type Fallback struct {
	AllowDaclMutation bool `json:"allowDaclMutation"`
}

// ProcessContainer holds ProcessContainer-only settings.
type ProcessContainer struct {
	CaptureDenials *CaptureDenials `json:"captureDenials,omitempty"`
}

// CaptureDenials asks MXC to record accesses the policy does not grant.
type CaptureDenials struct {
	Mode       string `json:"mode"`
	OutputPath string `json:"outputPath,omitempty"`
	RetainEtl  bool   `json:"retainEtl"`
}

// Marshal renders the request as compact JSON.
func (r *Request) Marshal() ([]byte, error) {
	return json.Marshal(r)
}
