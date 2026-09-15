// Egress proxy — hostname-pinning network allowlist enforcement.
//
// macOS Seatbelt cannot pin egress IPs (its network filters are port-only),
// and Linux Landlock NET rules are likewise port-granular. The proxy closes
// that gap the same way Claude Code's sandbox does: the engine starts an
// HTTP CONNECT + absolute-form proxy on 127.0.0.1 in the parent (which has
// unrestricted network), injects HTTP_PROXY/HTTPS_PROXY/NO_PROXY into the
// sandboxed process, and checks every outbound target against the hostname
// allowlist before dialing. Denied targets get HTTP 403 plus a
// "proxy-violation" audit entry. With no allowlist the proxy denies
// everything (fail closed).
//
// Hostname matching is exact or dot-boundary suffix only — never a bare
// string suffix — so "evil-nuget.org.attacker.com" cannot match "nuget.org"
// (the class of bypass published against endsWith()-style checks).

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// egressProxy is a loopback HTTP CONNECT proxy enforcing the config's
// hostname/IP/port allowlist. It runs in the engine (parent) process; the
// sandboxed child reaches it at 127.0.0.1:<port> via the injected
// HTTP(S)_PROXY variables.
type egressProxy struct {
	ln       net.Listener
	port     int
	exact    map[string]bool // lowercase exact hostnames
	suffixes []string        // ".example.com" suffixes from "*.example.com" patterns
	ips      map[string]bool // allowed IP literals (normalized)
	anyHost  bool            // an empty-host URL rule or bare "*" allows any host
	ports    map[int]bool    // explicit port allowlist; nil/empty means 80/443 only
	hasHosts bool            // whether any host/ip target is allowed at all

	mu         sync.Mutex
	conns      map[net.Conn]struct{}
	violations []config.AuditEntry
	closed     bool
}

// startEgressProxy binds the proxy to an ephemeral loopback port and compiles
// the allowlist from cfg (AllowHosts, AllowIPs, AllowURLRules hosts,
// AllowPorts).
func startEgressProxy(cfg config.ExecConfig) (*egressProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen egress proxy: %w", err)
	}
	p := &egressProxy{
		ln:    ln,
		port:  ln.Addr().(*net.TCPAddr).Port,
		exact: make(map[string]bool),
		ips:   make(map[string]bool),
		conns: make(map[net.Conn]struct{}),
	}

	addHost := func(h string) {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if h == "" || strings.HasPrefix(h, "~") {
			// Regex patterns cannot be safely honored as CONNECT-time
			// allowlist entries; require an exact or wildcard form.
			return
		}
		if h == "*" {
			p.anyHost = true
			return
		}
		if strings.HasPrefix(h, "*.") {
			p.suffixes = append(p.suffixes, strings.ToLower(h[1:])) // ".example.com"
			return
		}
		p.exact[h] = true
	}
	for _, h := range cfg.AllowHosts {
		addHost(h)
	}
	for _, r := range cfg.AllowURLRules {
		addHost(r.Host)
	}
	for _, ip := range cfg.AllowIPs {
		if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
			p.ips[parsed.String()] = true
		}
	}
	if len(cfg.AllowPorts) > 0 {
		p.ports = make(map[int]bool, len(cfg.AllowPorts))
		for _, port := range cfg.AllowPorts {
			if port > 0 {
				p.ports[port] = true
			}
		}
	}
	p.hasHosts = len(p.exact) > 0 || len(p.suffixes) > 0 || p.anyHost

	go p.acceptLoop()
	return p, nil
}

// envVars returns the proxy environment variables to inject into the
// sandboxed process. NO_PROXY covers loopback so local traffic never
// round-trips through the proxy.
func (p *egressProxy) envVars() map[string]string {
	url := fmt.Sprintf("http://127.0.0.1:%d", p.port)
	return map[string]string{
		"HTTP_PROXY":  url,
		"HTTPS_PROXY": url,
		"http_proxy":  url,
		"https_proxy": url,
		"NO_PROXY":    "localhost,127.0.0.1,::1",
		"no_proxy":    "localhost,127.0.0.1,::1",
	}
}

// injectEnv adds the proxy variables to cfg.Env (initializing the map if
// needed). Caller has already sanitized cfg.Env, and these names are neither
// credential-bearing nor loader-control, so they survive the sanitizer.
func (p *egressProxy) injectEnv(cfg *config.ExecConfig) {
	if cfg.Env == nil {
		cfg.Env = make(map[string]string, 6)
	}
	for k, v := range p.envVars() {
		cfg.Env[k] = v
	}
}

func (p *egressProxy) acceptLoop() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			conn.Close()
			return
		}
		p.conns[conn] = struct{}{}
		p.mu.Unlock()
		go func() {
			defer func() {
				p.mu.Lock()
				delete(p.conns, conn)
				p.mu.Unlock()
				conn.Close()
			}()
			p.handleConn(conn)
		}()
	}
}

// Close stops the listener and tears down live tunnels so the engine can
// exit promptly after the sandboxed command finishes.
func (p *egressProxy) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	conns := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.mu.Unlock()
	p.ln.Close()
	for _, c := range conns {
		c.Close()
	}
}

// violationsSnapshot returns and clears recorded audit entries.
func (p *egressProxy) violationsSnapshot() []config.AuditEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	v := p.violations
	p.violations = nil
	return v
}

// flushViolations emits collected proxy-violation audit entries to stderr as
// one JSON object per line — the same protocol the Node runner's
// parseAuditLog consumes for the Linux audit pipe.
func (p *egressProxy) flushViolations() {
	for _, v := range p.violationsSnapshot() {
		entry := map[string]string{
			"type":    v.Type,
			"target":  v.Target,
			"details": v.Detail,
		}
		if data, err := json.Marshal(entry); err == nil {
			fmt.Fprintf(os.Stderr, "%s\n", string(data))
		}
	}
}

// targetAllowed applies the hostname, IP, and port allowlists to a CONNECT /
// proxied request target. Fail closed: with no allowed hosts or IPs every
// target is denied.
func (p *egressProxy) targetAllowed(host string, port int) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if net.ParseIP(host) != nil {
		if !p.hasHosts && len(p.ips) == 0 {
			return false
		}
		if p.ips[host] {
			return portAllowed(p.ports, port)
		}
		return false
	}
	if p.anyHost {
		return portAllowed(p.ports, port)
	}
	if !p.hasHosts {
		return false
	}
	if p.exact[host] {
		return portAllowed(p.ports, port)
	}
	for _, suffix := range p.suffixes {
		if strings.HasSuffix(host, suffix) {
			return portAllowed(p.ports, port)
		}
	}
	return false
}

// portAllowed checks the port gate. An empty explicit list means "standard
// web ports only" — a conservative default that also matches the engine's
// Seatbelt behavior when host pinning is requested without ports.
func portAllowed(ports map[int]bool, port int) bool {
	if len(ports) == 0 {
		return port == 80 || port == 443
	}
	return ports[port]
}

// dialTarget dials host:port by name, so the resolver's own failover across
// A/AAAA records and record TTLs both apply. (An earlier version cached one
// pre-resolved address per allowlisted host to shave connect latency; that
// pinned the first address forever and broke CDN failover, and the latency it
// was working around was in fact the dropped-buffer bug fixed in handleConn.)
func (p *egressProxy) dialTarget(host, portStr string) (net.Conn, error) {
	return net.DialTimeout("tcp", net.JoinHostPort(host, portStr), 15*time.Second)
}

func (p *egressProxy) recordViolation(subject string) {
	p.mu.Lock()
	p.violations = append(p.violations, config.AuditEntry{
		Type:   "proxy-violation",
		Target: subject,
		Detail: "egress target denied by proxy allowlist",
	})
	p.mu.Unlock()
}

func (p *egressProxy) deny(conn net.Conn, subject string) {
	p.recordViolation(subject)
	fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\nX-Safer-Exec: egress-denied\r\n\r\n")
}

// handleConn serves one proxy client: a CONNECT tunnel request or an
// absolute-form plain-HTTP proxy request. Anything else is closed (the proxy
// speaks only proxy protocol).
func (p *egressProxy) handleConn(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReaderSize(conn, 8192)
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	requestLine = strings.TrimRight(requestLine, "\r\n")

	parts := strings.Fields(requestLine)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return
	}

	if parts[0] == "CONNECT" {
		host, portStr, splitErr := net.SplitHostPort(parts[1])
		if splitErr != nil {
			p.deny(conn, "CONNECT "+parts[1])
			return
		}
		port, _ := strconv.Atoi(portStr)
		if !p.targetAllowed(host, port) {
			p.deny(conn, "CONNECT "+parts[1])
			return
		}
		// Consume request headers before responding.
		for {
			line, err := reader.ReadString('\n')
			if err != nil || strings.TrimRight(line, "\r\n") == "" {
				break
			}
		}
		upstream, err := p.dialTarget(host, portStr)
		if err != nil {
			fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			return
		}
		defer upstream.Close()
		_ = conn.SetDeadline(time.Time{})
		fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		// Tunnel from `reader`, not `conn`: a client that pipelines its first
		// payload (e.g. the TLS ClientHello) in the same segment as the
		// CONNECT request has already had those bytes pulled into the bufio
		// buffer, and reading the raw conn would drop them.
		p.tunnel(conn, reader, upstream)
		return
	}

	// Absolute-form proxy request: GET http://host[:port]/path HTTP/1.1
	if strings.HasPrefix(parts[1], "http://") || strings.HasPrefix(parts[1], "https://") {
		rest := strings.SplitN(parts[1], "//", 2)[1]
		slash := strings.Index(rest, "/")
		hostPort := rest
		path := "/"
		if slash >= 0 {
			hostPort = rest[:slash]
			path = rest[slash:]
		}
		host, portStr, err := net.SplitHostPort(hostPort)
		if err != nil {
			host = hostPort
			if strings.HasPrefix(parts[1], "https://") {
				portStr = "443"
			} else {
				portStr = "80"
			}
		}
		port, _ := strconv.Atoi(portStr)
		if !p.targetAllowed(host, port) {
			p.deny(conn, parts[0]+" "+parts[1])
			return
		}
		upstream, dialErr := p.dialTarget(host, portStr)
		if dialErr != nil {
			fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			return
		}
		defer upstream.Close()
		_ = conn.SetDeadline(time.Time{})
		// Rewrite the request line to origin-form; the headers and body follow
		// untouched (the Host header the client sent is preserved) — they are
		// still unread in `reader`, so tunneling from `reader` forwards them.
		// Reading the raw conn instead would discard every header the client
		// coalesced into the same segment as its request line, leaving the
		// origin waiting forever for a request it can never complete.
		fmt.Fprintf(upstream, "%s %s %s\r\n", parts[0], path, parts[2])
		p.tunnel(conn, reader, upstream)
		return
	}
}

// tunnel copies bytes bidirectionally after a successful proxy handshake.
// clientSrc is the client-side reader — the buffered reader the request was
// parsed through, so that any bytes already drawn into its buffer are
// forwarded rather than lost. a is the same client connection, used only for
// writes and for the half-close.
func (p *egressProxy) tunnel(a net.Conn, clientSrc io.Reader, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, clientSrc)
	<-done
	// Closing the second direction unblocks the other copy.
	if tc, ok := a.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	if tc, ok := b.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	<-done
}
