package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdxgen/safer-exec/go/internal/config"
	"github.com/cdxgen/safer-exec/go/internal/tlsobserve"
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

// A learning run may reach any public host, but never the engine's own host:
// loopback services and link-local metadata endpoints are refused at dial
// time (403 plus a proxy-violation entry) and are not learned.
func TestLearningProxyRefusesHostLocalTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "local service")
	}))
	defer srv.Close()
	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	p, err := startLearningEgressProxy(config.ExecConfig{})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Close()

	for _, req := range []string{
		"CONNECT 127.0.0.1:" + portStr + " HTTP/1.1\r\nHost: 127.0.0.1:" + portStr + "\r\n\r\n",
		"GET http://localhost:" + portStr + "/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	} {
		status := proxyStatusLine(t, p.port, req)
		if !strings.Contains(status, " 403 ") {
			t.Errorf("%q: status %q, want 403", strings.SplitN(req, "\r\n", 2)[0], status)
		}
	}
	if got := p.connectedTargets(); len(got) != 0 {
		t.Errorf("host-local targets were learned: %v", got)
	}
	var refused int
	for _, v := range p.violationsSnapshot() {
		if v.Type == "proxy-violation" && strings.Contains(v.Detail, "host-local") {
			refused++
		}
	}
	if refused != 2 {
		t.Errorf("recorded %d host-local refusals, want 2", refused)
	}

	for ip, local := range map[string]bool{
		"127.0.0.1": true, "::1": true, "169.254.169.254": true, "fe80::1": true,
		"0.0.0.0": true, "224.0.0.251": true, "ff02::1": true,
		"10.0.0.1": false, "192.168.1.10": false, "93.184.216.34": false, "2606:4700::1111": false,
	} {
		if got := hostLocalIP(net.ParseIP(ip)); got != local {
			t.Errorf("hostLocalIP(%s) = %v, want %v", ip, got, local)
		}
	}
}

func TestNormalizeProxyHostAndRedaction(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM.":   "example.com",
		"[::1]":          "::1",
		"2001:DB8:0::1":  "2001:db8::1",
		" registry.org ": "registry.org",
	} {
		if got := normalizeProxyHost(in); got != want {
			t.Errorf("normalizeProxyHost(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"http://user:secret@evil.example/path?token=1": "http://evil.example/path",
		"https://tok@host.example:8443/a#frag":         "https://host.example:8443/a",
		"http://plain.example":                         "http://plain.example",
		"http://a@b@c.example/x":                       "http://c.example/x",
	} {
		if got := redactRequestTarget(in); got != want {
			t.Errorf("redactRequestTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

// Absolute-form requests may carry userinfo or a bracketed IPv6 literal with
// no port. The destination is the bare host, and credentials never reach the
// audit log.
func TestEgressProxyAbsoluteFormHostParsing(t *testing.T) {
	p, err := startEgressProxy(config.ExecConfig{
		AllowIPs:   []string{"::1"},
		AllowPorts: []int{80},
	})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Close()

	// Allowed: nothing may listen on [::1]:80, so a 502 (or a real answer)
	// proves the target parsed as ::1 port 80; a 403 would mean it did not.
	status := proxyStatusLine(t, p.port, "GET http://[::1]/probe HTTP/1.1\r\nHost: [::1]\r\nConnection: close\r\n\r\n")
	if strings.Contains(status, " 403 ") {
		t.Errorf("bracketed IPv6 target without a port was denied: %q", status)
	}

	status = proxyStatusLine(t, p.port, "GET http://user:hunter2@denied.example/x?k=v HTTP/1.1\r\nHost: denied.example\r\nConnection: close\r\n\r\n")
	if !strings.Contains(status, " 403 ") {
		t.Errorf("denied host: status %q, want 403", status)
	}
	for _, v := range p.violationsSnapshot() {
		if strings.Contains(v.Target, "hunter2") || strings.Contains(v.Target, "user:") {
			t.Errorf("credentials leaked into the audit entry: %+v", v)
		}
	}
}

// proxyStatusLine sends one raw request through the proxy and returns the
// response status line.
func proxyStatusLine(t *testing.T, proxyPort int, request string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// With traceCrypto the proxy reads the cleartext handshake of each tunnel
// (version, suite, key-exchange group, and up to TLS 1.2 the server key)
// while forwarding every byte unchanged.
func TestEgressProxyRecordsTLSParameters(t *testing.T) {
	body := strings.Repeat("x", 4<<20)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) })
	tls13 := httptest.NewTLSServer(handler)
	defer tls13.Close()
	tls12 := httptest.NewUnstartedServer(handler)
	tls12.TLS = &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}
	tls12.StartTLS()
	defer tls12.Close()

	var ports []int
	for _, s := range []*httptest.Server{tls13, tls12} {
		ports = append(ports, s.Listener.Addr().(*net.TCPAddr).Port)
	}
	p, err := startEgressProxy(config.ExecConfig{AllowIPs: []string{"127.0.0.1"}, AllowPorts: ports, TraceCrypto: true})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", p.port))
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "observe.test",
			CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
		},
	}}
	for _, s := range []*httptest.Server{tls13, tls12} {
		resp, err := client.Get(s.URL)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || len(got) != len(body) {
			t.Fatalf("body through the observed tunnel: %d bytes, %v", len(got), err)
		}
	}

	byHost := map[string]config.CipherInfo{}
	for _, c := range p.cipherSnapshot() {
		byHost[c.Host] = c
	}
	c13 := byHost[fmt.Sprintf("127.0.0.1:%d", ports[0])]
	if c13.Protocol != "TLSv1.3" || c13.Group != "X25519MLKEM768" || !c13.PostQuantum || c13.KeyExchange != "ECDHE+ML-KEM" ||
		c13.ServerName != "observe.test" || c13.Source != "proxy" || c13.IANAName == "" || c13.ServerKey != "" {
		t.Errorf("TLS 1.3 tunnel = %+v", c13)
	}
	c12 := byHost[fmt.Sprintf("127.0.0.1:%d", ports[1])]
	if c12.Protocol != "TLSv1.2" || c12.KeyExchange != "ECDHE" || c12.Group == "" || c12.ServerKey == "" || c12.CertSignature == "" ||
		c12.Encryption != "AES" || c12.Mode != "GCM" {
		t.Errorf("TLS 1.2 tunnel = %+v", c12)
	}
}

// proxyChainPKI builds a three-level PKI and returns the server certificate
// (leaf first) plus the parsed leaf, intermediate and root.
func proxyChainPKI(t *testing.T) (tls.Certificate, *x509.Certificate, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	rootKey, interKey, leafKey := testKey(t), testKey(t), testKey(t)
	root := testCert(t, "proxy-test-root-ca", true, rootKey, nil, nil)
	inter := testCert(t, "proxy-test-intermediate", true, interKey, root, rootKey)
	leaf := testCert(t, "proxy-test-leaf", false, leafKey, inter, interKey)
	server := tls.Certificate{
		Certificate: [][]byte{leaf.Raw, inter.Raw, root.Raw},
		PrivateKey:  leafKey,
	}
	return server, leaf, inter, root
}

// A TLS 1.2 tunnel through the proxy records the whole chain the server
// presented, leaf first, with the SPKI hashes a distrust list keys on.
func TestEgressProxyRecordsCertificateChain(t *testing.T) {
	serverCert, leaf, inter, root := proxyChainPKI(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	srv.TLS = &tls.Config{
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
	srv.StartTLS()
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	p, err := startEgressProxy(config.ExecConfig{
		AllowIPs:    []string{"127.0.0.1"},
		AllowPorts:  []int{port},
		TraceCrypto: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", p.port))
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "observe.test"},
	}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	var entry *config.CipherInfo
	for _, c := range p.cipherSnapshot() {
		if c.Host == fmt.Sprintf("127.0.0.1:%d", port) {
			e := c
			entry = &e
		}
	}
	if entry == nil {
		t.Fatal("no cipher entry for the tunnel")
	}
	if entry.ServerKey != "ECDSA-P-256" || entry.CertSignature != "ECDSA-SHA256" {
		t.Errorf("leaf fields: %+v", entry)
	}
	want := []*x509.Certificate{leaf, inter, root}
	if len(entry.Chain) != len(want) {
		t.Fatalf("chain = %+v", entry.Chain)
	}
	for i, cert := range want {
		got := entry.Chain[i]
		certSum := sha256.Sum256(cert.Raw)
		spkiSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if got.CertSha256 != hex.EncodeToString(certSum[:]) || got.SpkiSha256 != hex.EncodeToString(spkiSum[:]) ||
			got.Name != cert.Subject.CommonName || got.Subject != cert.Subject.String() || got.Issuer != cert.Issuer.String() {
			t.Errorf("chain[%d] = %+v (cert %s)", i, got, cert.Subject.CommonName)
		}
		if got.IsCA != cert.IsCA || got.KeyName != "ECDSA-P256" || got.KeyBits != 256 {
			t.Errorf("chain[%d] flags = %+v", i, got)
		}
	}
	if !entry.Chain[2].SelfSigned || entry.Chain[1].SelfSigned || entry.Chain[0].SelfSigned {
		t.Errorf("self-signed flags: %+v", entry.Chain)
	}
}

// The recorded chain is part of the dedup key: the same target presenting a
// different chain under otherwise equal parameters is a new entry, and the
// same chain is recorded once.
func TestEgressProxyChainDistinguishesEqualHandshakes(t *testing.T) {
	p, err := startEgressProxy(config.ExecConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	base := tlsobserve.Handshake{Version: 0x0303, CipherSuite: 0xC02F, ServerKey: "ECDSA-P-256"}
	withA, withB := base, base
	withA.Chain = []tlsobserve.ChainCert{{Name: "leaf-a", CertSha256: "aa11", SpkiSha256: "0101"}}
	withB.Chain = []tlsobserve.ChainCert{{Name: "leaf-b", CertSha256: "bb22", SpkiSha256: "0202"}}
	p.recordTLS("same.host:443", withA)
	p.recordTLS("same.host:443", withB)
	p.recordTLS("same.host:443", withA)
	got := p.cipherSnapshot()
	if len(got) != 2 {
		t.Fatalf("recorded %d entries, want 2 (equal parameters, different chains): %+v", len(got), got)
	}
	if got[0].Chain[0].Name == got[1].Chain[0].Name {
		t.Fatalf("entries were not distinguished by chain: %+v", got)
	}
}

// IP-literal targets must match IP-literal allowlist entries however the
// entry was written: in AllowIPs, in AllowHosts (Node's DNS step resolves
// nothing for a literal, so the literal only ever reaches the engine as a
// host entry), as a bracketed IPv6 literal, in an AllowURLRules host, or as a
// CIDR. A literal that no entry covers stays denied.
func TestEgressProxyIPLiteralAllowlist(t *testing.T) {
	cases := []struct {
		name   string
		cfg    config.ExecConfig
		target string
		port   int
		want   bool
	}{
		{"AllowIPs v4", config.ExecConfig{AllowIPs: []string{"127.0.0.1"}}, "127.0.0.1", 443, true},
		{"AllowIPs v6", config.ExecConfig{AllowIPs: []string{"::1"}}, "::1", 443, true},
		{"AllowIPs bracketed v6", config.ExecConfig{AllowIPs: []string{"[::1]"}}, "::1", 443, true},
		{"AllowHosts v4", config.ExecConfig{AllowHosts: []string{"127.0.0.1"}}, "127.0.0.1", 443, true},
		{"AllowHosts v6", config.ExecConfig{AllowHosts: []string{"::1"}}, "::1", 443, true},
		{"AllowHosts bracketed v6", config.ExecConfig{AllowHosts: []string{"[::1]"}}, "::1", 443, true},
		{"AllowHosts v6 spelled long", config.ExecConfig{AllowHosts: []string{"0:0:0:0:0:0:0:1"}}, "::1", 443, true},
		{"target v6 spelled long", config.ExecConfig{AllowHosts: []string{"::1"}}, "0:0:0:0:0:0:0:1", 443, true},
		{"AllowURLRules host", config.ExecConfig{AllowURLRules: []config.AllowURLRule{{Host: "127.0.0.1"}}}, "127.0.0.1", 443, true},
		{"CIDR v4 in AllowIPs", config.ExecConfig{AllowIPs: []string{"127.0.0.0/8"}}, "127.0.0.5", 443, true},
		{"CIDR v4 in AllowHosts", config.ExecConfig{AllowHosts: []string{"10.1.0.0/16"}}, "10.1.9.9", 443, true},
		{"CIDR v6", config.ExecConfig{AllowIPs: []string{"fd00::/8"}}, "fd12::1", 443, true},
		{"CIDR outside", config.ExecConfig{AllowIPs: []string{"10.1.0.0/16"}}, "10.2.0.1", 443, false},
		{"other v4 literal", config.ExecConfig{AllowHosts: []string{"127.0.0.1"}}, "127.0.0.2", 443, false},
		{"other v6 literal", config.ExecConfig{AllowHosts: []string{"::1"}}, "::2", 443, false},
		{"v4-mapped v6 of allowed v4", config.ExecConfig{AllowIPs: []string{"127.0.0.1"}}, "::ffff:127.0.0.1", 443, true},
		{"v4-mapped v6 of other v4", config.ExecConfig{AllowIPs: []string{"127.0.0.1"}}, "::ffff:127.0.0.2", 443, false},
		{"port gate still applies", config.ExecConfig{AllowHosts: []string{"127.0.0.1"}}, "127.0.0.1", 22, false},
		{"explicit port", config.ExecConfig{AllowHosts: []string{"127.0.0.1"}, AllowPorts: []int{9460}}, "127.0.0.1", 9460, true},
		// Names that only resolve to an address must not match a literal
		// entry, and numeric spellings the resolver would accept must not
		// be treated as the allowed literal.
		{"localhost is not 127.0.0.1", config.ExecConfig{AllowHosts: []string{"127.0.0.1"}}, "localhost", 443, false},
		{"decimal spelling", config.ExecConfig{AllowHosts: []string{"127.0.0.1"}}, "2130706433", 443, false},
		{"hex spelling", config.ExecConfig{AllowHosts: []string{"127.0.0.1"}}, "0x7f000001", 443, false},
		{"octal spelling", config.ExecConfig{AllowHosts: []string{"127.0.0.1"}}, "0177.0.0.1", 443, false},
		{"short spelling", config.ExecConfig{AllowHosts: []string{"127.0.0.1"}}, "127.1", 443, false},
		{"literal does not allow its suffix names", config.ExecConfig{AllowHosts: []string{"127.0.0.1"}}, "x.127.0.0.1", 443, false},
		{"metadata not allowed by loopback entry", config.ExecConfig{AllowHosts: []string{"127.0.0.1"}}, "169.254.169.254", 80, false},
		{"metadata not allowed by wildcard host", config.ExecConfig{AllowHosts: []string{"*.example.com"}}, "169.254.169.254", 80, false},
		{"0.0.0.0/0 does not open metadata", config.ExecConfig{AllowHosts: []string{"0.0.0.0/0"}}, "169.254.169.254", 80, false},
		{"0.0.0.0/0 does not open mapped metadata", config.ExecConfig{AllowIPs: []string{"0.0.0.0/0"}}, "::ffff:169.254.169.254", 80, false},
		{"::/0 does not open link-local v6", config.ExecConfig{AllowIPs: []string{"::/0"}}, "fe80::1", 80, false},
		{"0.0.0.0/0 does not open unspecified", config.ExecConfig{AllowIPs: []string{"0.0.0.0/0"}}, "0.0.0.0", 80, false},
		{"link-local CIDR does not open itself", config.ExecConfig{AllowIPs: []string{"169.254.0.0/16"}}, "169.254.169.254", 80, false},
		{"exact metadata literal still works", config.ExecConfig{AllowIPs: []string{"169.254.169.254"}}, "169.254.169.254", 80, true},
		{"0.0.0.0/0 does not open Alibaba metadata", config.ExecConfig{AllowIPs: []string{"0.0.0.0/0"}}, "100.100.100.200", 80, false},
		{"::/0 does not open AWS IMDS v6", config.ExecConfig{AllowIPs: []string{"::/0"}}, "fd00:ec2::254", 80, false},
		{"::/0 does not open v4-compatible metadata", config.ExecConfig{AllowIPs: []string{"::/0"}}, "::169.254.169.254", 80, false},
		{"::/0 does not open NAT64 metadata", config.ExecConfig{AllowIPs: []string{"::/0"}}, "64:ff9b::169.254.169.254", 80, false},
		{"::/0 does not open NAT64 loopback", config.ExecConfig{AllowIPs: []string{"::/0"}}, "64:ff9b::127.0.0.1", 80, false},
		{"::/0 still allows public v6", config.ExecConfig{AllowIPs: []string{"::/0"}}, "2001:db8::1", 80, true},
		{"exact Alibaba metadata literal still works", config.ExecConfig{AllowIPs: []string{"100.100.100.200"}}, "100.100.100.200", 80, true},
		{"0.0.0.0/0 still allows public literals", config.ExecConfig{AllowIPs: []string{"0.0.0.0/0"}}, "93.184.216.34", 80, true},
		{"unbalanced bracket entry is not an IP", config.ExecConfig{AllowHosts: []string{"[::1"}}, "::1", 80, false},
		{"bare star host does not allow literals", config.ExecConfig{AllowHosts: []string{"*"}}, "127.0.0.1", 443, false},
		{"bare star host does not allow metadata", config.ExecConfig{AllowHosts: []string{"*"}}, "169.254.169.254", 80, false},
		{"bare star still allows names", config.ExecConfig{AllowHosts: []string{"*"}}, "example.org", 443, true},
		{"empty list denies", config.ExecConfig{}, "127.0.0.1", 443, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := startEgressProxy(tc.cfg)
			if err != nil {
				t.Fatalf("start proxy: %v", err)
			}
			defer p.Close()
			if got := p.targetAllowed(tc.target, tc.port); got != tc.want {
				t.Errorf("targetAllowed(%q, %d) = %v, want %v", tc.target, tc.port, got, tc.want)
			}
		})
	}
}

// End to end through the proxy: a CONNECT to an allowed IP literal tunnels,
// both for 127.0.0.1 and ::1, and a literal that is not allowed gets 403.
func TestEgressProxyConnectsToAllowedIPLiterals(t *testing.T) {
	for _, tc := range []struct {
		name, listen, entry, other string
	}{
		{"v4", "127.0.0.1:0", "127.0.0.1", "127.0.0.2"},
		{"v6", "[::1]:0", "::1", "::2"},
		{"cidr v4", "127.0.0.1:0", "127.0.0.0/8", "10.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", tc.listen)
			if err != nil {
				t.Skipf("cannot listen on %s: %v", tc.listen, err)
			}
			defer ln.Close()
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					c.Write([]byte("hello"))
					c.Close()
				}
			}()
			addr := ln.Addr().(*net.TCPAddr)
			p, err := startEgressProxy(config.ExecConfig{AllowHosts: []string{tc.entry}, AllowPorts: []int{addr.Port}})
			if err != nil {
				t.Fatalf("start proxy: %v", err)
			}
			defer p.Close()
			target := net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))
			status := proxyStatusLine(t, p.port, fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target))
			if !strings.Contains(status, "200") {
				t.Errorf("CONNECT %s = %q, want 200", target, status)
			}
			denied := net.JoinHostPort(tc.other, strconv.Itoa(addr.Port))
			status = proxyStatusLine(t, p.port, fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", denied, denied))
			if !strings.Contains(status, "403") {
				t.Errorf("CONNECT %s = %q, want 403", denied, status)
			}
		})
	}
}

// Every deny that exists today stays: a learning run refuses loopback,
// link-local (cloud metadata) and unspecified literals however they are
// spelled, and the allowlist change must not make them reachable.
func TestLearningProxyStillRefusesHostLocalLiterals(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "169.254.169.254", "fe80::1", "0.0.0.0", "::", "224.0.0.1", "::ffff:169.254.169.254"} {
		if !hostLocalIP(net.ParseIP(ip)) {
			t.Errorf("hostLocalIP(%s) = false, want true", ip)
		}
	}
	p, err := startLearningEgressProxy(config.ExecConfig{AllowHosts: []string{"127.0.0.1", "169.254.169.254", "169.254.0.0/16"}})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Close()
	for _, target := range []string{"127.0.0.1:80", "169.254.169.254:80", "[::1]:80"} {
		status := proxyStatusLine(t, p.port, fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target))
		if !strings.Contains(status, "403") {
			t.Errorf("learning CONNECT %s = %q, want 403", target, status)
		}
	}
}

// A bare "*" allows names but never IP literals; a name that resolves to a
// host-local or metadata address (numeric spellings, localhost) is refused
// at dial time, while an exact entry for that name still connects.
func TestEgressProxyWildcardRefusesHostLocalResolution(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("hello"))
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	p, err := startEgressProxy(config.ExecConfig{AllowHosts: []string{"*"}, AllowPorts: []int{port}})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Close()
	for _, host := range []string{"localhost", "2130706433", "0x7f000001", "127.1"} {
		target := net.JoinHostPort(host, strconv.Itoa(port))
		status := proxyStatusLine(t, p.port, fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target))
		if strings.Contains(status, "200") {
			t.Errorf("CONNECT %s = %q, want refused", target, status)
		}
		status = proxyStatusLine(t, p.port, fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", target, target))
		if strings.Contains(status, "200") {
			t.Errorf("GET http://%s/ = %q, want refused", target, status)
		}
	}
	exact, err := startEgressProxy(config.ExecConfig{AllowHosts: []string{"localhost"}, AllowPorts: []int{port}})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer exact.Close()
	target := net.JoinHostPort("localhost", strconv.Itoa(port))
	if status := proxyStatusLine(t, exact.port, fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)); !strings.Contains(status, "200") {
		t.Errorf("exact localhost entry: CONNECT %s = %q, want 200", target, status)
	}
}
