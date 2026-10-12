package mxc

import "testing"

// probeBaseContainer is wxc-exec --probe output captured on Windows 11 25H2
// (build 26200.9457).
const probeBaseContainer = `{
  "tier": "base-container",
  "needsDaclAugmentation": false,
  "warnings": [],
  "probes": {
    "baseContainerApiPresent": true,
    "nativeCaptureAvailable": true,
    "guardedCaptureAvailable": false,
    "bfscfgPresent": false,
    "bfsCompiledIn": false,
    "baseContainerSupportsDenyPaths": true,
    "baseContainerSupportsEnumeratePaths": false,
    "baseContainerSupportsIngressHostLoopbackAllow": false,
    "baseContainerSupportsIdentitylessLoopbackProxy": true,
    "isolationSessionAvailable": false,
    "hyperlightAvailable": false,
    "uiCapabilities": {"canBlockClipboardRead": true}
  }
}`

func TestParseProbe(t *testing.T) {
	p, err := ParseProbe([]byte(probeBaseContainer))
	if err != nil {
		t.Fatal(err)
	}
	if p.Tier != TierBaseContainer || p.MutatesHost() {
		t.Errorf("tier %q mutates %v", p.Tier, p.MutatesHost())
	}
	if !p.Flag("baseContainerSupportsIdentitylessLoopbackProxy") || p.Flag("baseContainerSupportsIngressHostLoopbackAllow") {
		t.Error("flags misread")
	}
	if p.Flag("uiCapabilities") || p.Flag("missing") {
		t.Error("non-boolean or absent probe read as true")
	}
	var nilProbe *ProbeResult
	if nilProbe.Flag("x") || nilProbe.MutatesHost() {
		t.Error("nil probe must report nothing")
	}
}

func TestParseProbeDaclTier(t *testing.T) {
	p, err := ParseProbe([]byte(`{"tier":"appcontainer-dacl","needsDaclAugmentation":true,"warnings":["run wxc-host-prep prepare-system-drive"],"probes":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !p.MutatesHost() || len(p.Warnings) != 1 {
		t.Errorf("dacl tier: %+v", p)
	}
	p, _ = ParseProbe([]byte(`{"tier":"appcontainer-bfs","needsDaclAugmentation":false,"probes":{}}`))
	if p.MutatesHost() {
		t.Error("BFS tier does not mutate host ACLs")
	}
}

func TestParseProbeErrors(t *testing.T) {
	for _, in := range []string{``, `not json`, `{"probes":{}}`} {
		if _, err := ParseProbe([]byte(in)); err == nil {
			t.Errorf("ParseProbe(%q) accepted", in)
		}
	}
}
