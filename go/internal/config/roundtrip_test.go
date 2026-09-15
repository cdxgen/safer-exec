package config

import (
	"encoding/json"
	"testing"
)

// Round-trip coverage for the newer hardening/isolation fields: learn output
// must serialize them and MergePolicies must preserve/union them so the
// Discover -> Refine -> Iterate -> Deploy loop stops dropping hardening.
func TestPolicyFileRoundTripNewFields(t *testing.T) {
	raw := `{
		"name": "rt",
		"blockJIT": true,
		"proxyEgress": true,
		"tmpOverlayPaths": ["/tmp/ovl"],
		"seccompFilters": [{"policy": "ALLOW read; DEFAULT KILL"}],
		"useReaper": true,
		"procHardening": true,
		"submountEnforce": true,
		"dieWithParent": true,
		"newSession": true,
		"setUpDev": true,
		"bindUseFd": true,
		"allowUserns": false,
		"allowEnvs": ["CI"]
	}`
	var p PolicyFile
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !p.BlockJIT || !p.ProxyEgress || !p.UseReaper || !p.ProcHardening ||
		!p.SubmountEnforce || !p.DieWithParent || !p.NewSession || !p.SetUpDev || !p.BindUseFd {
		t.Errorf("boolean fields did not round-trip: %+v", p)
	}
	if len(p.TmpOverlayPaths) != 1 || p.TmpOverlayPaths[0] != "/tmp/ovl" {
		t.Errorf("tmpOverlayPaths did not round-trip: %v", p.TmpOverlayPaths)
	}
	if len(p.SeccompFilters) != 1 || p.SeccompFilters[0].Policy != "ALLOW read; DEFAULT KILL" {
		t.Errorf("seccompFilters did not round-trip: %v", p.SeccompFilters)
	}
	if len(p.AllowEnvs) != 1 || p.AllowEnvs[0] != "CI" {
		t.Errorf("allowEnvs did not round-trip: %v", p.AllowEnvs)
	}

	// Serialize again and confirm the JSON keys exist.
	out, err := json.Marshal(&p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{"blockJIT", "proxyEgress", "tmpOverlayPaths", "seccompFilters",
		"useReaper", "procHardening", "submountEnforce", "dieWithParent", "newSession",
		"setUpDev", "bindUseFd", "allowEnvs"} {
		if !containsKey(string(out), key) {
			t.Errorf("serialized policy missing key %q: %s", key, out)
		}
	}
}

func containsKey(jsonStr, key string) bool {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}

func TestMergePoliciesNewHardeningFields(t *testing.T) {
	base := &PolicyFile{
		BlockJIT:       true,
		ProxyEgress:    true,
		AllowEnvs:      []string{"CI"},
		SeccompFilters: []SeccompFilterSpec{{Policy: "ALLOW read; DEFAULT KILL"}},
	}
	observed := &PolicyFile{
		UseReaper:       true,
		SubmountEnforce: true,
		AllowEnvs:       []string{"CI", "HOME"},
		SeccompFilters:  []SeccompFilterSpec{{Policy: "ALLOW read; DEFAULT KILL"}, {Policy: "ALLOW write; DEFAULT KILL"}},
	}
	merged := MergePolicies(base, observed)
	if !merged.BlockJIT || !merged.ProxyEgress || !merged.UseReaper || !merged.SubmountEnforce {
		t.Errorf("merge dropped hardening booleans: %+v", merged)
	}
	if len(merged.AllowEnvs) != 2 {
		t.Errorf("allowEnvs union wrong: %v", merged.AllowEnvs)
	}
	if len(merged.SeccompFilters) != 2 {
		t.Errorf("seccomp filter dedupe/union wrong: %v", merged.SeccompFilters)
	}
}

func TestOverlayExecConfigToPolicy(t *testing.T) {
	cfg := ExecConfig{
		BlockJIT:              true,
		ProxyEgress:           true,
		DenyPersistenceWrites: true,
		BlockInterpreters:     true,
		UseReaper:             true,
		ProcHardening:         true,
		SubmountEnforce:       true,
		TmpOverlayPaths:       []string{"/cache"},
		SeccompFilters: []SeccompFilterSpec{
			{Policy: "ALLOW read; DEFAULT KILL"},
			{Program: "base64-blob-should-not-persist"},
		},
		AllowEnvs:     []string{"CI"},
		ProtectSystem: "strict",
	}
	policy := &PolicyFile{}
	policy = OverlayExecConfigToPolicy(cfg, policy)

	if !policy.BlockJIT || !policy.ProxyEgress || !policy.DenyPersistenceWrites ||
		!policy.BlockInterpreters || !policy.UseReaper || !policy.ProcHardening || !policy.SubmountEnforce {
		t.Errorf("overlay dropped hardening flags: %+v", policy)
	}
	if len(policy.SeccompFilters) != 1 || policy.SeccompFilters[0].Policy != "ALLOW read; DEFAULT KILL" {
		t.Errorf("overlay must persist only kafel policy strings, got: %v", policy.SeccompFilters)
	}
	if len(policy.TmpOverlayPaths) != 1 || policy.TmpOverlayPaths[0] != "/cache" {
		t.Errorf("tmpOverlayPaths overlay wrong: %v", policy.TmpOverlayPaths)
	}
	if len(policy.AllowEnvs) != 1 || policy.AllowEnvs[0] != "CI" {
		t.Errorf("allowEnvs overlay wrong: %v", policy.AllowEnvs)
	}
	if policy.ProtectSystem != "strict" {
		t.Errorf("protectSystem overlay wrong: %q", policy.ProtectSystem)
	}

	// Overlay must be additive, not clobber existing policy state.
	existing := &PolicyFile{AllowEnvs: []string{"HOME"}, TmpOverlayPaths: []string{"/other"}}
	merged := OverlayExecConfigToPolicy(cfg, existing)
	if len(merged.AllowEnvs) != 2 || len(merged.TmpOverlayPaths) != 2 {
		t.Errorf("overlay not additive: allowEnvs=%v tmpOverlay=%v", merged.AllowEnvs, merged.TmpOverlayPaths)
	}
}

func TestOverlayExecConfigNilPolicy(t *testing.T) {
	if got := OverlayExecConfigToPolicy(ExecConfig{BlockJIT: true}, nil); got != nil {
		t.Errorf("nil policy must pass through, got %v", got)
	}
}
