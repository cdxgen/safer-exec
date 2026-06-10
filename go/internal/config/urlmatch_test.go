package config

import (
	"testing"
)

// ---------- AllowURLRule matching tests ----------

func TestMatchURLRule_ExactHost(t *testing.T) {
	rules := CompileURLRules([]AllowURLRule{
		{Host: "registry.npmjs.org", Protocol: "https", Port: 443},
	})

	if !MatchesAny(rules, "GET", "https", "registry.npmjs.org", 443, "/package") {
		t.Fatal("expected match for exact host")
	}
	if MatchesAny(rules, "GET", "https", "evil.npmjs.org", 443, "/package") {
		t.Fatal("expected no match for different host")
	}
}

func TestMatchURLRule_WildcardHost(t *testing.T) {
	rules := CompileURLRules([]AllowURLRule{
		{Host: "*.npmjs.org", Protocol: "https"},
	})

	if !MatchesAny(rules, "GET", "https", "registry.npmjs.org", 443, "/") {
		t.Fatal("expected wildcard host match")
	}
	// Multi-level wildcard should not match (*.npmjs.org ≠ a.b.npmjs.org)
	if MatchesAny(rules, "GET", "https", "a.b.npmjs.org", 443, "/") {
		t.Fatal("expected no multi-level wildcard match")
	}
	// Wrong domain
	if MatchesAny(rules, "GET", "https", "registry.pypi.org", 443, "/") {
		t.Fatal("expected no match for different domain")
	}
}

func TestMatchURLRule_RegexHost(t *testing.T) {
	rules := CompileURLRules([]AllowURLRule{
		{Host: `~^(registry|api)\.npmjs\.org$`, Protocol: "https"},
	})

	if !MatchesAny(rules, "GET", "https", "registry.npmjs.org", 443, "/") {
		t.Fatal("expected regex host match: registry")
	}
	if !MatchesAny(rules, "GET", "https", "api.npmjs.org", 443, "/") {
		t.Fatal("expected regex host match: api")
	}
	if MatchesAny(rules, "GET", "https", "evil.npmjs.org", 443, "/") {
		t.Fatal("expected no regex host match: evil")
	}
}

func TestMatchURLRule_PathPrefix(t *testing.T) {
	rules := CompileURLRules([]AllowURLRule{
		{Host: "registry.npmjs.org", PathPrefix: "/npm/v1/"},
	})

	if !MatchesAny(rules, "GET", "https", "registry.npmjs.org", 443, "/npm/v1/security") {
		t.Fatal("expected path prefix match")
	}
	if MatchesAny(rules, "GET", "https", "registry.npmjs.org", 443, "/other/endpoint") {
		t.Fatal("expected no match for different path")
	}
}

func TestMatchURLRule_PathRegex(t *testing.T) {
	rules := CompileURLRules([]AllowURLRule{
		{Host: "registry.npmjs.org", PathPrefix: `~^/npm/v[0-9]+/`},
	})

	if !MatchesAny(rules, "GET", "https", "registry.npmjs.org", 443, "/npm/v1/security") {
		t.Fatal("expected regex path match v1")
	}
	if !MatchesAny(rules, "GET", "https", "registry.npmjs.org", 443, "/npm/v2/bulk") {
		t.Fatal("expected regex path match v2")
	}
	if MatchesAny(rules, "GET", "https", "registry.npmjs.org", 443, "/npm/vX/bulk") {
		t.Fatal("expected no match for non-numeric version")
	}
}

func TestMatchURLRule_PathGlob(t *testing.T) {
	rules := CompileURLRules([]AllowURLRule{
		{Host: "registry.npmjs.org", PathPrefix: "/npm/*/security"},
	})

	if !MatchesAny(rules, "GET", "https", "registry.npmjs.org", 443, "/npm/v1/security") {
		t.Fatal("expected glob path match")
	}
}

func TestMatchURLRule_Methods(t *testing.T) {
	rules := CompileURLRules([]AllowURLRule{
		{Host: "api.example.com", Methods: []string{"GET", "HEAD"}},
	})

	if !MatchesAny(rules, "GET", "https", "api.example.com", 443, "/") {
		t.Fatal("expected GET method match")
	}
	if !MatchesAny(rules, "head", "https", "api.example.com", 443, "/") {
		t.Fatal("expected case-insensitive method match")
	}
	if MatchesAny(rules, "POST", "https", "api.example.com", 443, "/") {
		t.Fatal("expected no match for POST method")
	}
}

func TestMatchURLRule_Protocol(t *testing.T) {
	rules := CompileURLRules([]AllowURLRule{
		{Host: "example.com", Protocol: "https"},
	})

	if !MatchesAny(rules, "GET", "https", "example.com", 443, "/") {
		t.Fatal("expected https protocol match")
	}
	if MatchesAny(rules, "GET", "http", "example.com", 80, "/") {
		t.Fatal("expected no match for http protocol")
	}
}

func TestMatchURLRule_EmptyRules_Permissive(t *testing.T) {
	rules := CompileURLRules(nil)
	if !MatchesAny(rules, "GET", "https", "any.host.com", 443, "/any/path") {
		t.Fatal("expected empty rules to be permissive")
	}
}

func TestMatchURLRule_MultipleRules(t *testing.T) {
	rules := CompileURLRules([]AllowURLRule{
		{Host: "registry.npmjs.org", Protocol: "https"},
		{Host: "api.github.com", Protocol: "https", Methods: []string{"GET"}},
	})

	if !MatchesAny(rules, "POST", "https", "registry.npmjs.org", 443, "/") {
		t.Fatal("expected match against first rule")
	}
	if !MatchesAny(rules, "GET", "https", "api.github.com", 443, "/") {
		t.Fatal("expected match against second rule")
	}
	if MatchesAny(rules, "POST", "https", "api.github.com", 443, "/") {
		t.Fatal("expected no match: POST blocked on api.github.com")
	}
}

func TestMatchURLRule_InvalidRegex_FallsBackToExact(t *testing.T) {
	// Invalid regex — should not panic, falls back to exact match
	rules := CompileURLRules([]AllowURLRule{
		{Host: "~[invalid regex"},
	})
	// hostRe will be nil; falls back to exact match of "~[invalid regex"
	if MatchesAny(rules, "GET", "https", "registry.npmjs.org", 443, "/") {
		t.Fatal("expected no match when regex fails to compile")
	}
}

// ---------- SynthesiseURLRules tests ----------

func TestSynthesiseURLRules_EmptyInput(t *testing.T) {
	rules := SynthesiseURLRules(nil)
	if len(rules) != 0 {
		t.Fatalf("expected empty rules, got %d", len(rules))
	}
}

func TestSynthesiseURLRules_SingleEntry(t *testing.T) {
	entries := []HTTPAccessEntry{
		{Method: "GET", Host: "registry.npmjs.org", Protocol: "https", Port: 443, Path: "/npm/v1/security"},
	}
	rules := SynthesiseURLRules(entries)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Host != "registry.npmjs.org" {
		t.Errorf("unexpected host: %s", rules[0].Host)
	}
	if rules[0].Port != 443 {
		t.Errorf("unexpected port: %d", rules[0].Port)
	}
}

func TestSynthesiseURLRules_GroupsByHostPort(t *testing.T) {
	entries := []HTTPAccessEntry{
		{Method: "GET", Host: "registry.npmjs.org", Protocol: "https", Port: 443, Path: "/npm/v1/a"},
		{Method: "POST", Host: "registry.npmjs.org", Protocol: "https", Port: 443, Path: "/npm/v1/b"},
		{Method: "GET", Host: "api.github.com", Protocol: "https", Port: 443, Path: "/repos"},
	}
	rules := SynthesiseURLRules(entries)
	if len(rules) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(rules))
	}
}

func TestSynthesiseURLRules_CommonPathPrefix(t *testing.T) {
	entries := []HTTPAccessEntry{
		{Host: "reg.npmjs.org", Protocol: "https", Port: 443, Path: "/npm/v1/security/advisories"},
		{Host: "reg.npmjs.org", Protocol: "https", Port: 443, Path: "/npm/v1/security/bulk"},
		{Host: "reg.npmjs.org", Protocol: "https", Port: 443, Path: "/npm/v1/packages/foo"},
	}
	rules := SynthesiseURLRules(entries)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].PathPrefix != "/npm/v1/" {
		t.Errorf("unexpected path prefix: %q (expected /npm/v1/)", rules[0].PathPrefix)
	}
}

func TestLongestCommonPathPrefix_EmptyInput(t *testing.T) {
	result := longestCommonPathPrefix(nil)
	if result != "/" {
		t.Errorf("expected /, got %q", result)
	}
}

func TestLongestCommonPathPrefix_SinglePath(t *testing.T) {
	result := longestCommonPathPrefix([]string{"/npm/v1/security"})
	if result != "/npm/v1/" {
		t.Errorf("expected /npm/v1/, got %q", result)
	}
}

func TestLongestCommonPathPrefix_DivergentPaths(t *testing.T) {
	result := longestCommonPathPrefix([]string{"/npm/a", "/pip/b"})
	if result != "/" {
		t.Errorf("expected /, got %q", result)
	}
}
