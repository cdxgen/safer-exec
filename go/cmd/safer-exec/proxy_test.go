package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// The matcher must be exact-or-dot-suffix: a bare suffix check would let
// "evil-nuget.org.attacker.com" match "nuget.org" — the published bypass
// class against endsWith()-style allowlists.
func TestEgressProxyHostMatching(t *testing.T) {
	cfg := config.ExecConfig{
		AllowHosts: []string{"registry.npmjs.org", "*.golang.org"},
		AllowIPs:   []string{"10.1.2.3"},
		AllowPorts: []int{443, 8080},
	}
	p, err := startEgressProxy(cfg)
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Close()

	cases := []struct {
		host    string
		port    int
		allowed bool
	}{
		{"registry.npmjs.org", 443, true},
		{"REGISTRY.NPMJS.org", 443, true},               // case-insensitive
		{"registry.npmjs.org.", 443, true},              // trailing FQDN dot
		{"proxy.golang.org", 443, true},                 // wildcard subdomain
		{"deep.sub.golang.org", 443, true},              // multi-label under wildcard
		{"registry.npmjs.org.attacker.com", 443, false}, // suffix attack
		{"evilregistry.npmjs.org", 443, false},          // prefix attack
		{"nuget.org", 443, false},                       // not in list
		{"registry.npmjs.org", 8080, true},              // allowed port
		{"registry.npmjs.org", 22, false},               // blocked port
		{"10.1.2.3", 443, true},                         // allowed IP literal
		{"10.1.2.4", 443, false},                        // other IP literal
	}
	for _, tc := range cases {
		if got := p.targetAllowed(tc.host, tc.port); got != tc.allowed {
			t.Errorf("targetAllowed(%q, %d) = %v, want %v", tc.host, tc.port, got, tc.allowed)
		}
	}
}

// Port gate default: with no explicit AllowPorts only the standard web ports
// pass even when the host matches.
func TestEgressProxyDefaultPorts(t *testing.T) {
	p, err := startEgressProxy(config.ExecConfig{AllowHosts: []string{"example.org"}})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Close()
	if !p.targetAllowed("example.org", 80) || !p.targetAllowed("example.org", 443) {
		t.Errorf("default port gate must allow 80/443")
	}
	if p.targetAllowed("example.org", 8080) {
		t.Errorf("default port gate must deny non-web ports")
	}
}

// Fail closed: no hosts and no IPs means every target is denied.
func TestEgressProxyFailsClosed(t *testing.T) {
	p, err := startEgressProxy(config.ExecConfig{})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Close()
	if p.targetAllowed("anything.example", 443) {
		t.Errorf("empty allowlist must deny every host")
	}
	if p.targetAllowed("127.0.0.1", 80) {
		t.Errorf("empty allowlist must deny IP literals")
	}
}

func TestEgressProxyEnvVars(t *testing.T) {
	p, err := startEgressProxy(config.ExecConfig{AllowHosts: []string{"x"}})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Close()
	env := p.envVars()
	want := fmt.Sprintf("http://127.0.0.1:%d", p.port)
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if env[k] != want {
			t.Errorf("%s = %q, want %q", k, env[k], want)
		}
	}
	if !strings.Contains(env["NO_PROXY"], "127.0.0.1") {
		t.Errorf("NO_PROXY must cover loopback: %q", env["NO_PROXY"])
	}
}

// Live CONNECT round trip: an allowed host tunnels to a local test server
// (simulated by mapping the test server's port into AllowPorts and its
// 127.0.0.1 address into AllowIPs), and a denied host gets 403 plus a
// recorded violation.
func TestEgressProxyConnectRoundTrip(t *testing.T) {
	server := httptest.NewServer(nil)
	defer server.Close()
	_, serverPort, _ := net.SplitHostPort(server.Listener.Addr().String())
	port := 0
	fmt.Sscanf(serverPort, "%d", &port)

	cfg := config.ExecConfig{
		AllowIPs:   []string{"127.0.0.1"},
		AllowPorts: []int{port},
	}
	p, err := startEgressProxy(cfg)
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Close()

	// Allowed: CONNECT to 127.0.0.1:<test server port> and speak raw HTTP.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p.port), 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", port, port)
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("expected 200 Connection Established, got %q", line)
	}

	// Denied: CONNECT to a non-allowed host.
	conn2, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p.port), 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn2.Close()
	_ = conn2.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn2, "CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")
	resp, err := bufio.NewReader(conn2).ReadString('\n')
	if err != nil {
		t.Fatalf("read denial: %v", err)
	}
	if !strings.Contains(resp, "403") {
		t.Fatalf("expected 403 for denied host, got %q", resp)
	}

	var violations, connects []config.AuditEntry
	for _, e := range p.violationsSnapshot() {
		switch e.Type {
		case "proxy-violation":
			violations = append(violations, e)
		case "proxy-connect":
			connects = append(connects, e)
		}
	}
	if len(violations) != 1 {
		t.Fatalf("expected one proxy-violation entry, got %v", violations)
	}
	if !strings.Contains(violations[0].Target, "evil.example.com") {
		t.Fatalf("violation target must name the denied host: %+v", violations[0])
	}
	want := fmt.Sprintf("127.0.0.1:%d", port)
	if len(connects) != 1 || connects[0].Target != want || connects[0].Detail != "connect" {
		t.Fatalf("expected one proxy-connect entry for %s, got %v", want, connects)
	}
}

// Allowed targets are recorded once per host:port, without the request path
// or query, and a denied absolute-form request is logged without its query.
func TestEgressProxyRecordsConnectsAndRedactsQueries(t *testing.T) {
	p, err := startEgressProxy(config.ExecConfig{AllowHosts: []string{"registry.example.org"}})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Close()
	p.recordConnect("registry.example.org:443", "connect")
	p.recordConnect("registry.example.org:443", "connect")
	p.recordConnect("registry.example.org:80", "http")
	if got := redactRequestTarget("http://evil.example.com/p?token=secret#f"); got != "http://evil.example.com/p" {
		t.Fatalf("query not redacted: %q", got)
	}
	entries := p.violationsSnapshot()
	if len(entries) != 2 {
		t.Fatalf("expected two deduplicated proxy-connect entries, got %v", entries)
	}
	for _, e := range entries {
		if e.Type != "proxy-connect" || strings.ContainsAny(e.Target, "/?") {
			t.Fatalf("unexpected entry %+v", e)
		}
	}
}

// A proxied plain-HTTP request must reach the origin complete. The request
// line is rewritten to origin-form, but the headers the client coalesced into
// the same segment are already inside the proxy's bufio buffer; forwarding
// them is what makes the request well-formed. Regression test: tunneling from
// the raw connection instead dropped every header, so the origin blocked
// forever waiting for a request terminator and the client saw a hang.
func TestEgressProxyAbsoluteFormForwardsHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s ua=%s", r.Host, r.Header.Get("User-Agent"))
	}))
	defer srv.Close()

	hostPort := strings.TrimPrefix(srv.URL, "http://")
	_, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatalf("split test server address: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	p, err := startEgressProxy(config.ExecConfig{
		AllowIPs:   []string{"127.0.0.1"},
		AllowPorts: []int{port},
	})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Close()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p.port), 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// One write, as a real client does: request line and headers together.
	fmt.Fprintf(conn, "GET http://%s/probe HTTP/1.1\r\nHost: %s\r\nUser-Agent: probe-agent\r\nConnection: close\r\n\r\n",
		hostPort, hostPort)

	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read proxied response: %v", err)
	}
	resp := string(body)
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("expected a 200 from the origin through the proxy, got %q", resp)
	}
	if !strings.Contains(resp, "ua=probe-agent") {
		t.Fatalf("client headers were not forwarded to the origin: %q", resp)
	}
	if !strings.Contains(resp, "host="+hostPort) {
		t.Fatalf("Host header was not preserved: %q", resp)
	}
}

// A client may pipeline its first tunnel payload (typically the TLS
// ClientHello) in the same segment as the CONNECT request. Those bytes land in
// the proxy's read buffer during request parsing, and must still reach the
// upstream. Regression test: they were previously dropped, which stalled the
// TLS handshake and looked like an intermittent network hang.
func TestEgressProxyConnectForwardsPipelinedPayload(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstream.Close()

	echoed := make(chan string, 1)
	go func() {
		c, err := upstream.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil {
			echoed <- ""
			return
		}
		echoed <- string(buf[:n])
		_, _ = c.Write([]byte("ack"))
	}()

	port := upstream.Addr().(*net.TCPAddr).Port
	p, err := startEgressProxy(config.ExecConfig{
		AllowIPs:   []string{"127.0.0.1"},
		AllowPorts: []int{port},
	})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Close()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p.port), 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// CONNECT and first payload coalesced into a single write.
	fmt.Fprintf(conn, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\nEARLY-PAYLOAD", port, port)

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("expected 200 Connection Established, got %q", line)
	}

	select {
	case got := <-echoed:
		if got != "EARLY-PAYLOAD" {
			t.Fatalf("pipelined payload lost or corrupted: upstream received %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the pipelined payload (dropped read buffer)")
	}
}
