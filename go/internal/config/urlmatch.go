// Package config — URL rule matching utilities.
//
// MatchURLRule tests a single HTTP request (method, host, port, protocol,
// path) against an AllowURLRule. Matching semantics:
//
//   - Empty rule fields are wildcards (match anything).
//   - Host and PathPrefix fields support three syntaxes:
//     exact string, glob wildcard ("*.npmjs.org", "/api/*"),
//     or Go regexp when the value is prefixed with "~"
//     (e.g. "~^registry\\.npmjs\\.org$", "~^/npm/v[0-9]+/").
//   - Methods are case-insensitive. An empty Methods slice allows any method.
package config

import (
	"regexp"
	"strings"
)

// compiledRule is a pre-compiled version of AllowURLRule for efficient matching.
// We compile regexps once, not on every request.
type compiledRule struct {
	raw        AllowURLRule
	hostRe     *regexp.Regexp // non-nil when host starts with "~"
	hostIsGlob bool           // true when host contains "*"
	pathRe     *regexp.Regexp // non-nil when pathPrefix starts with "~"
	pathIsGlob bool           // true when pathPrefix contains "*"
}

// CompileURLRules pre-compiles a slice of AllowURLRule into compiledRules.
// Invalid regexps are silently treated as exact-string matches.
func CompileURLRules(rules []AllowURLRule) []compiledRule {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		cr := compiledRule{raw: r}

		// Host
		if strings.HasPrefix(r.Host, "~") {
			// Regexp syntax
			re, err := regexp.Compile(r.Host[1:])
			if err == nil {
				cr.hostRe = re
			}
		} else if strings.Contains(r.Host, "*") {
			cr.hostIsGlob = true
		}

		// PathPrefix
		if strings.HasPrefix(r.PathPrefix, "~") {
			re, err := regexp.Compile(r.PathPrefix[1:])
			if err == nil {
				cr.pathRe = re
			}
		} else if strings.Contains(r.PathPrefix, "*") {
			cr.pathIsGlob = true
		}

		compiled = append(compiled, cr)
	}
	return compiled
}

// MatchesAny returns true if the given HTTP request matches at least one of the
// compiled rules. Returns true immediately for an empty rule set (permissive).
func MatchesAny(rules []compiledRule, method, protocol, host string, port int, path string) bool {
	if len(rules) == 0 {
		return true
	}
	for _, cr := range rules {
		if matchRule(cr, method, protocol, host, port, path) {
			return true
		}
	}
	return false
}

// matchRule tests a single compiled rule.
func matchRule(cr compiledRule, method, protocol, host string, port int, path string) bool {
	r := cr.raw

	// Protocol check
	if r.Protocol != "" && !strings.EqualFold(r.Protocol, protocol) {
		return false
	}

	// Host check
	if r.Host != "" && !matchHostPattern(cr, host) {
		return false
	}

	// Port check (0 = any)
	if r.Port != 0 && r.Port != port {
		return false
	}

	// PathPrefix check
	if r.PathPrefix != "" && r.PathPrefix != "/" {
		if !matchPathPattern(cr, path) {
			return false
		}
	}

	// Method check (case-insensitive)
	if len(r.Methods) > 0 {
		methodUpper := strings.ToUpper(method)
		found := false
		for _, m := range r.Methods {
			if strings.ToUpper(m) == methodUpper {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// matchHostPattern matches a host against a compiled rule's host field.
func matchHostPattern(cr compiledRule, host string) bool {
	r := cr.raw
	if cr.hostRe != nil {
		return cr.hostRe.MatchString(host)
	}
	if cr.hostIsGlob {
		return globMatch(r.Host, host)
	}
	return strings.EqualFold(r.Host, host)
}

// matchPathPattern matches a URL path against a compiled rule's pathPrefix field.
func matchPathPattern(cr compiledRule, path string) bool {
	r := cr.raw
	if cr.pathRe != nil {
		return cr.pathRe.MatchString(path)
	}
	if cr.pathIsGlob {
		return globMatch(r.PathPrefix, path)
	}
	return strings.HasPrefix(path, r.PathPrefix)
}

// globMatch implements simple glob matching where:
//   - "*" matches any sequence of non-dot characters in host context
//     but any sequence of characters in path context.
//
// For host patterns:  "*.npmjs.org" matches "registry.npmjs.org" but NOT "a.b.npmjs.org".
// For path patterns:  "/npm/*" matches "/npm/anything/here".
func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return strings.EqualFold(pattern, s)
	}

	hostContext := strings.Contains(pattern, ".")
	remaining := s

	for i, part := range parts {
		if part == "" {
			// If trailing "*", ensure the rest of the string is valid
			if i == len(parts)-1 {
				if hostContext && strings.Contains(remaining, ".") {
					return false
				}
				return true
			}
			continue
		}

		idx := strings.Index(strings.ToLower(remaining), strings.ToLower(part))
		if idx < 0 {
			return false
		}

		// The characters we skipped over to find 'part'
		skipped := remaining[:idx]

		// If this is the very first literal segment (and pattern doesn't start with "*"),
		// it MUST match exactly at the beginning of 's'.
		if i == 0 && idx > 0 {
			return false
		}

		// If we are in host context, a wildcard cannot span across a dot (e.g. *.com cannot match a.b.com)
		// We only enforce this for the 'skipped' portions which correspond to the "*" characters.
		if hostContext && i > 0 && strings.Contains(skipped, ".") {
			return false
		}

		remaining = remaining[idx+len(part):]
	}

	// Must match the entire string unless the pattern ended with "*"
	if len(remaining) > 0 && parts[len(parts)-1] != "" {
		return false
	}

	return true
}

// SynthesiseURLRules converts a list of HTTPAccessEntry observations into a
// minimal set of AllowURLRules. Entries are grouped by (protocol, host, port)
// and paths are collected per group. Methods are unioned per group.
func SynthesiseURLRules(entries []HTTPAccessEntry) []AllowURLRule {
	type groupKey struct {
		protocol string
		host     string
		port     int
	}
	type groupData struct {
		methods map[string]bool
		paths   []string
	}

	groups := make(map[groupKey]*groupData)
	for _, e := range entries {
		k := groupKey{protocol: e.Protocol, host: e.Host, port: e.Port}
		g, ok := groups[k]
		if !ok {
			g = &groupData{methods: make(map[string]bool)}
			groups[k] = g
		}
		if e.Method != "" {
			g.methods[strings.ToUpper(e.Method)] = true
		}
		if e.Path != "" {
			// Find longest common prefix of all paths for this group
			g.paths = append(g.paths, e.Path)
		}
	}

	rules := make([]AllowURLRule, 0, len(groups))
	for k, g := range groups {
		prefix := longestCommonPathPrefix(g.paths)
		methods := make([]string, 0, len(g.methods))
		for m := range g.methods {
			methods = append(methods, m)
		}
		rules = append(rules, AllowURLRule{
			Protocol:   k.protocol,
			Host:       k.host,
			Port:       k.port,
			PathPrefix: prefix,
			Methods:    methods,
		})
	}
	return rules
}

// longestCommonPathPrefix returns the longest common prefix of a list of paths,
// truncated at a "/" boundary so it remains a valid path prefix.
func longestCommonPathPrefix(paths []string) string {
	if len(paths) == 0 {
		return "/"
	}
	if len(paths) == 1 {
		// Use parent directory as prefix so it covers the exact path
		idx := strings.LastIndex(paths[0], "/")
		if idx <= 0 {
			return "/"
		}
		return paths[0][:idx+1]
	}

	prefix := paths[0]
	for _, p := range paths[1:] {
		for !strings.HasPrefix(p, prefix) {
			// Trim to parent "/"
			idx := strings.LastIndex(prefix[:len(prefix)-1], "/")
			if idx < 0 {
				return "/"
			}
			prefix = prefix[:idx+1]
		}
	}
	if prefix == "" {
		return "/"
	}
	return prefix
}
