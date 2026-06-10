// Package httptrace provides HTTP URL and method tracing for sandboxed processes
// via eBPF uprobes on TLS write functions (SSL_write, GnuTLS gnutls_record_send,
// and Go's crypto/tls.(*Conn).Write). Captures plaintext HTTP/1.x and HTTP/2
// requests before TLS encryption, parses the method and URL, and emits
// structured events.
//
// HTTP/2 support:
// HTTP/2 uses HPACK-compressed binary framing (RFC 7540/7541). The tracer
// maintains a per-connection hpack.Decoder (keyed by the SSL* pointer) so
// that the dynamic compression table stays consistent across multiple writes
// on the same TLS connection.
//
// Platform support:
//   - Linux (amd64, arm64): full eBPF implementation; requires kernel >= 5.8,
//     CAP_BPF + CAP_PERFMON in the init user namespace.
//   - All other platforms: no-op stub — New() returns ErrUnsupported.
package httptrace

import "errors"

// ErrUnsupported is returned by New() on platforms where eBPF tracing is
// not available (non-Linux, unsupported arch, kernel < 5.8, or missing caps).
var ErrUnsupported = errors.New("httptrace: eBPF HTTP tracing not supported on this platform/kernel")

// Source identifies which TLS library produced an event.
type Source uint8

const (
	SourceSSLWrite   Source = 0 // OpenSSL / BoringSSL SSL_write
	SourceGoTLS      Source = 1 // Go crypto/tls (*Conn).Write
	SourceGnuTLSSend Source = 2 // GnuTLS gnutls_record_send
)

func (s Source) String() string {
	switch s {
	case SourceSSLWrite:
		return "ssl_write_uprobe"
	case SourceGoTLS:
		return "go_tls_uprobe"
	case SourceGnuTLSSend:
		return "gnutls_uprobe"
	default:
		return "unknown"
	}
}

// HTTPEvent is a single HTTP request observed in a TLS write buffer.
type HTTPEvent struct {
	// PID is the host PID of the process that made the TLS write call.
	PID uint32
	// Method is the HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS).
	Method string
	// Path is the request path (e.g. "/v1/packages").
	Path string
	// Host is the value of the Host header (e.g. "registry.npmjs.org").
	Host string
	// Protocol is the protocol used ("http" or "https").
	Protocol string
	// Port is the TCP port of the request.
	Port int
	// Query is the query parameters of the request.
	Query string
	// Body is the request body.
	Body string
	// Source identifies which TLS library was intercepted.
	Source Source
}

// Tracer attaches eBPF uprobes to TLS write functions and emits HTTPEvents
// for every HTTP/1.x request observed in the captured buffers.
type Tracer interface {
	// AddPID adds a PID to the eBPF filter so only traffic from that
	// process (and its descendants) is captured. Safe to call concurrently.
	AddPID(pid uint32) error
	// RemovePID removes a PID from the eBPF filter.
	RemovePID(pid uint32) error
	// SetTraceAll bypasses the PID filter and captures from every process
	// that loads a supported TLS library. Use with caution on busy systems.
	SetTraceAll(enabled bool) error
	// Events returns the channel on which HTTPEvents are delivered.
	// The channel is closed when Close is called.
	Events() <-chan HTTPEvent
	// AttachGoTLS attaches a uprobe to Go's crypto/tls.(*Conn).Write in the executable.
	AttachGoTLS(exePath string) error
	// AttachStaticOpenSSL attaches the OpenSSL SSL_write uprobe directly to the target executable.
	AttachStaticOpenSSL(exePath string) error
	// Close detaches all probes and releases eBPF resources.
	Close() error
}
