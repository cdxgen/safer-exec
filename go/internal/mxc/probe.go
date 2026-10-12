package mxc

import (
	"encoding/json"
	"fmt"
)

// ProbeResult is the output of "wxc-exec --probe": the containment tier MXC
// would select on this host and the host capability facts behind it. The
// probe is read-only and does not start a sandbox.
type ProbeResult struct {
	Tier                  string          `json:"tier"`
	NeedsDaclAugmentation bool            `json:"needsDaclAugmentation"`
	Warnings              []string        `json:"warnings"`
	Probes                map[string]any  `json:"probes"`
	Raw                   json.RawMessage `json:"-"`
}

// Containment tiers reported by the probe.
const (
	// TierBaseContainer is the OS process security environment
	// (CreateProcessSecurityEnvironment): OS-enforced filesystem grants, WFP
	// egress filters and per-container proxy configuration, with no host
	// modification.
	TierBaseContainer = "base-container"
	// TierAppContainerBfs is an AppContainer brokered through the OS
	// filesystem broker; it does not modify host ACLs.
	TierAppContainerBfs = "appcontainer-bfs"
	// TierAppContainerDacl is an AppContainer that is granted access by
	// adding ACEs to host security descriptors for the duration of the run.
	TierAppContainerDacl = "appcontainer-dacl"
)

// ParseProbe decodes probe output.
func ParseProbe(data []byte) (*ProbeResult, error) {
	var r ProbeResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse wxc-exec --probe output: %w", err)
	}
	if r.Tier == "" {
		return nil, fmt.Errorf("wxc-exec --probe output has no tier")
	}
	r.Raw = append(json.RawMessage(nil), data...)
	return &r, nil
}

// Flag returns a boolean probe fact (false when absent or not boolean).
func (r *ProbeResult) Flag(name string) bool {
	if r == nil {
		return false
	}
	b, _ := r.Probes[name].(bool)
	return b
}

// MutatesHost reports whether the selected tier changes host security
// descriptors (the AppContainer + DACL fallback).
func (r *ProbeResult) MutatesHost() bool {
	return r != nil && (r.NeedsDaclAugmentation || r.Tier == TierAppContainerDacl)
}
