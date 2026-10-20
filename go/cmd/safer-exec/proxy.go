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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cdxgen/safer-exec/go/internal/config"
	"github.com/cdxgen/safer-exec/go/internal/httptrace"
	"github.com/cdxgen/safer-exec/go/internal/tlsobserve"
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
	learn    bool            // learning mode: allow every target, record each one
	// observeTLS records the cleartext handshake parameters of each CONNECT
	// tunnel (traceCrypto): version, cipher suite, key-exchange group and, up
	// to TLS 1.2, the server key. The tunnel itself is never altered.
	observeTLS bool

	mu         sync.Mutex
	conns      map[net.Conn]struct{}
	violations []config.AuditEntry
	connected  map[string]bool // host:port targets already recorded as proxy-connect
	ciphers    []config.CipherInfo
	cipherSeen map[string]bool
	closed     bool
}

// maxProxyConnectEntries caps distinct proxy-connect audit entries so a
// command that fans out to many hosts cannot grow the audit log unbounded.
const maxProxyConnectEntries = 4096

// maxProxyCipherEntries caps the distinct TLS parameter sets recorded.
const maxProxyCipherEntries = 1024

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

		connected:  make(map[string]bool),
		cipherSeen: make(map[string]bool),
		observeTLS: cfg.TraceCrypto || cfg.CBOMOutputPath != "",
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

// startLearningEgressProxy starts a proxy that allows every public target and
// records each distinct host:port it forwards (as proxy-connect entries and
// through connectedTargets). Learning runs use it to discover the hostnames a
// command needs; the allowlist fields of cfg are ignored. Addresses that only
// make sense on the engine's own host — loopback, link-local (including cloud
// metadata endpoints), unspecified and multicast — are refused at dial time,
// whatever name resolved to them, so a learning run cannot use the proxy to
// reach host-local services or teach the next run to allow them.
func startLearningEgressProxy(cfg config.ExecConfig) (*egressProxy, error) {
	p, err := startEgressProxy(cfg)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.learn = true
	p.mu.Unlock()
	return p, nil
}

// connectedTargets returns the distinct host:port targets the proxy forwarded,
// sorted.
func (p *egressProxy) connectedTargets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.connected))
	for t := range p.connected {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
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

// cipherSnapshot returns the TLS parameter sets the proxy observed.
func (p *egressProxy) cipherSnapshot() []config.CipherInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]config.CipherInfo(nil), p.ciphers...)
}

// recordTLS records one tunnel's handshake parameters once per distinct set.
// The chain's certificate hashes are part of the key: two servers that agree
// on every negotiated parameter but present different chains stay separate
// entries.
func (p *egressProxy) recordTLS(target string, h tlsobserve.Handshake) {
	info := proxyCipherInfo(target, h)
	keyParts := []string{info.Host, info.ServerName, info.IANAName, info.Name, info.Protocol, info.Group, info.ServerKey}
	for _, cc := range info.Chain {
		keyParts = append(keyParts, cc.CertSha256)
	}
	key := strings.Join(keyParts, "|")
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cipherSeen[key] || len(p.ciphers) >= maxProxyCipherEntries {
		return
	}
	p.cipherSeen[key] = true
	p.ciphers = append(p.ciphers, info)
}

// proxyCipherInfo describes an observed handshake in the form the Linux
// crypto tracer uses, so both feed the same audit entries and CBOM.
func proxyCipherInfo(target string, h tlsobserve.Handshake) config.CipherInfo {
	s := tlsobserve.Suite(h.CipherSuite)
	info := config.CipherInfo{
		Name:           s.Name,
		IANAID:         h.CipherSuite,
		Protocol:       tlsobserve.VersionName(h.Version),
		Bits:           s.EncryptionBits,
		KeyExchange:    s.KeyExchange,
		Authentication: s.Authentication,
		Encryption:     s.Encryption,
		EncryptionBits: s.EncryptionBits,
		Hash:           s.Hash,
		Mode:           s.Mode,
		Host:           target,
		ServerName:     h.ServerName,
		ECH:            h.ECH,
		ServerKey:      h.ServerKey,
		CertSignature:  h.CertSignature,
		Source:         "proxy",
	}
	for _, cc := range h.Chain {
		info.Chain = append(info.Chain, config.CertChainEntry{
			Name:             cc.Name,
			Subject:          cc.Subject,
			Issuer:           cc.Issuer,
			CertSha256:       cc.CertSha256,
			SpkiSha256:       cc.SpkiSha256,
			SpkiSha256Base64: cc.SpkiSha256Base64,
			KeyName:          cc.KeyName,
			KeyBits:          cc.KeyBits,
			IsCA:             cc.IsCA,
			SelfSigned:       cc.SelfSigned,
		})
	}
	if s.Known {
		info.IANAName = s.Name
	}
	if name, ok := httptrace.CipherNameByID(h.CipherSuite); ok {
		info.Name = name
	}
	switch {
	case h.Group != 0:
		info.Group = tlsobserve.GroupName(h.Group)
		info.PostQuantum = tlsobserve.GroupPostQuantum(h.Group)
		if info.KeyExchange == "" {
			info.KeyExchange = tlsobserve.GroupKeyExchange(h.Group)
		}
	case h.DHBits > 0:
		info.Group = fmt.Sprintf("DH-%d", h.DHBits)
	}
	return info
}

// violationsSnapshot returns and clears recorded audit entries.
func (p *egressProxy) violationsSnapshot() []config.AuditEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	v := p.violations
	p.violations = nil
	return v
}

// flushViolations emits the collected proxy-violation and proxy-connect
// audit entries, one JSON object each, over the report channel (or stderr).
func (p *egressProxy) flushViolations() {
	for _, v := range p.violationsSnapshot() {
		entry := map[string]string{
			"type":    v.Type,
			"target":  v.Target,
			"details": v.Detail,
		}
		if data, err := json.Marshal(entry); err == nil {
			emitAuditLine(data, os.Stderr)
		}
	}
}

// targetAllowed applies the hostname, IP, and port allowlists to a CONNECT /
// proxied request target. Fail closed: with no allowed hosts or IPs every
// target is denied.
func (p *egressProxy) targetAllowed(host string, port int) bool {
	host = normalizeProxyHost(host)
	if p.learning() {
		return host != "" && port > 0 && port <= 65535
	}
	if ip := net.ParseIP(host); ip != nil {
		if !p.hasHosts && len(p.ips) == 0 {
			return false
		}
		if p.ips[ip.String()] {
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
	d := net.Dialer{Timeout: 15 * time.Second}
	if p.learning() {
		// Checked per attempted address, after resolution, so a public name
		// that resolves to a host-local address is refused too.
		d.Control = func(_, address string, _ syscall.RawConn) error {
			h, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(h); ip == nil || hostLocalIP(ip) {
				return errHostLocalTarget
			}
			return nil
		}
	}
	return d.Dial("tcp", net.JoinHostPort(host, portStr))
}

// errHostLocalTarget marks a learning-mode dial refused because the target
// address belongs to the engine's host rather than the network.
var errHostLocalTarget = errors.New("host-local address refused while learning")

// hostLocalIP reports addresses a learning run must not reach through the
// proxy: loopback, link-local (169.254.0.0/16 holds cloud metadata services),
// unspecified and multicast.
func hostLocalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

func (p *egressProxy) learning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.learn
}

// normalizeProxyHost lower-cases a request host, strips IPv6 brackets and a
// trailing root dot, and canonicalizes IP literals, so allowlist checks and
// recorded targets agree on one spelling per host.
func normalizeProxyHost(host string) string {
	host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(host), "["), "]")
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

// dialFailed answers a client whose upstream dial failed: a learning-mode
// refusal of a host-local address is a policy denial (403 plus a
// proxy-violation entry), anything else a 502.
func (p *egressProxy) dialFailed(conn net.Conn, subject string, err error) {
	if errors.Is(err, errHostLocalTarget) {
		p.recordViolationDetail(subject, "host-local address refused while learning")
		fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\nX-Safer-Exec: egress-denied\r\n\r\n")
		return
	}
	fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

func (p *egressProxy) recordViolation(subject string) {
	p.recordViolationDetail(subject, "egress target denied by proxy allowlist")
}

func (p *egressProxy) recordViolationDetail(subject, detail string) {
	p.mu.Lock()
	p.violations = append(p.violations, config.AuditEntry{
		Type:   "proxy-violation",
		Target: subject,
		Detail: detail,
	})
	p.mu.Unlock()
}

// recordConnect records an allowed egress target once per host:port as a
// "proxy-connect" audit entry. Only the authority is kept: request paths and
// query strings can carry credentials. This is the egress inventory the proxy
// can see on every platform, including macOS where eBPF URL tracing is absent.
func (p *egressProxy) recordConnect(hostPort, kind string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.connected[hostPort] || len(p.connected) >= maxProxyConnectEntries {
		return
	}
	p.connected[hostPort] = true
	p.violations = append(p.violations, config.AuditEntry{
		Type:   "proxy-connect",
		Target: hostPort,
		Detail: kind,
	})
}

// redactRequestTarget drops the query string, fragment and any userinfo
// ("user:password@") from an absolute-form request target before it is
// written to the audit log.
func redactRequestTarget(target string) string {
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	if scheme, rest, ok := strings.Cut(target, "://"); ok {
		authority, path, hasPath := strings.Cut(rest, "/")
		if at := strings.LastIndex(authority, "@"); at >= 0 {
			authority = authority[at+1:]
		}
		target = scheme + "://" + authority
		if hasPath {
			target += "/" + path
		}
	}
	return target
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
			p.dialFailed(conn, "CONNECT "+parts[1], err)
			return
		}
		defer upstream.Close()
		target := net.JoinHostPort(normalizeProxyHost(host), portStr)
		p.recordConnect(target, "connect")
		_ = conn.SetDeadline(time.Time{})
		fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		// Tunnel from `reader`, not `conn`: a client that pipelines its first
		// payload (e.g. the TLS ClientHello) in the same segment as the
		// CONNECT request has already had those bytes pulled into the bufio
		// buffer, and reading the raw conn would drop them.
		var clientSrc, serverSrc io.Reader = reader, upstream
		if p.observeTLS {
			obs := tlsobserve.New(func(h tlsobserve.Handshake) { p.recordTLS(target, h) })
			defer obs.Close()
			clientSrc = obs.ClientReader(reader)
			serverSrc = obs.ServerReader(upstream)
		}
		p.tunnel(conn, clientSrc, upstream, serverSrc)
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
		// Userinfo is not part of the destination (and must not be logged).
		if at := strings.LastIndex(hostPort, "@"); at >= 0 {
			hostPort = hostPort[at+1:]
		}
		host, portStr, err := net.SplitHostPort(hostPort)
		if err != nil {
			// No port: a bare name or a bracketed IPv6 literal.
			host = strings.TrimSuffix(strings.TrimPrefix(hostPort, "["), "]")
			if strings.HasPrefix(parts[1], "https://") {
				portStr = "443"
			} else {
				portStr = "80"
			}
		}
		port, _ := strconv.Atoi(portStr)
		if !p.targetAllowed(host, port) {
			p.deny(conn, parts[0]+" "+redactRequestTarget(parts[1]))
			return
		}
		upstream, dialErr := p.dialTarget(host, portStr)
		if dialErr != nil {
			p.dialFailed(conn, parts[0]+" "+redactRequestTarget(parts[1]), dialErr)
			return
		}
		defer upstream.Close()
		p.recordConnect(net.JoinHostPort(normalizeProxyHost(host), portStr), "http")
		_ = conn.SetDeadline(time.Time{})
		// Rewrite the request line to origin-form; the headers and body follow
		// untouched (the Host header the client sent is preserved) — they are
		// still unread in `reader`, so tunneling from `reader` forwards them.
		// Reading the raw conn instead would discard every header the client
		// coalesced into the same segment as its request line, leaving the
		// origin waiting forever for a request it can never complete.
		fmt.Fprintf(upstream, "%s %s %s\r\n", parts[0], path, parts[2])
		p.tunnel(conn, reader, upstream, upstream)
		return
	}
}

// tunnel copies bytes bidirectionally after a successful proxy handshake.
// clientSrc is the client-side reader — the buffered reader the request was
// parsed through, so that any bytes already drawn into its buffer are
// forwarded rather than lost. a is the same client connection, used only for
// writes and for the half-close. serverSrc reads from b, possibly through the
// TLS observer.
func (p *egressProxy) tunnel(a net.Conn, clientSrc io.Reader, b net.Conn, serverSrc io.Reader) {
	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, serverSrc)
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
