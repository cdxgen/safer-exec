//go:build linux && (amd64 || arm64)

// Package httptrace — Linux eBPF implementation.
// Attaches uprobes to TLS write functions to capture plaintext HTTP/1.x
// and HTTP/2 requests before encryption and emits structured events via a
// ring buffer.  HTTP/2 HEADERS frames are decoded using per-connection HPACK
// decoders keyed by the SSL* pointer captured from the uprobe arguments.
package httptrace

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/net/http2/hpack"
)

const (
	flagTraceAll uint8 = 0x01
	maxBufSize         = 4096
)

// sslEvent mirrors the BPF-side struct ssl_event (ssl_trace.c).
// Fields and alignment must match the C struct exactly.
// Layout: PID(4) + Len(4) + Source(1) + Pad(7) + ConnID(8) + Buf(4096)
//
//	offset  0: PID     uint32
//	offset  4: Len     uint32
//	offset  8: Source  uint8
//	offset  9: Pad     [7]uint8
//	offset 16: ConnID  uint64
//	offset 24: Buf     [4096]uint8
type sslEvent struct {
	PID    uint32
	Len    uint32
	Source uint8
	Pad    [7]uint8
	ConnID uint64
	Buf    [maxBufSize]byte
}

// bpfObjects holds the loaded BPF programs and maps after collection creation.
type bpfObjects struct {
	// Programs
	ProbeSSLWrite   *ebpf.Program `ebpf:"probe_ssl_write"`
	ProbeGnuTLSSend *ebpf.Program `ebpf:"probe_gnutls_send"`
	ProbeGoTLSWrite *ebpf.Program `ebpf:"probe_go_tls_write"`
	// Maps
	Events      *ebpf.Map `ebpf:"events"`
	PidFilter   *ebpf.Map `ebpf:"pid_filter"`
	ConfigFlags *ebpf.Map `ebpf:"config_flags"`
}

func (o *bpfObjects) Close() {
	if o.ProbeSSLWrite != nil {
		o.ProbeSSLWrite.Close()
	}
	if o.ProbeGnuTLSSend != nil {
		o.ProbeGnuTLSSend.Close()
	}
	if o.ProbeGoTLSWrite != nil {
		o.ProbeGoTLSWrite.Close()
	}
	if o.Events != nil {
		o.Events.Close()
	}
	if o.PidFilter != nil {
		o.PidFilter.Close()
	}
	if o.ConfigFlags != nil {
		o.ConfigFlags.Close()
	}
}

// linuxTracer is the Linux eBPF implementation of Tracer.
type linuxTracer struct {
	mu        sync.Mutex
	objs      bpfObjects
	links     []link.Link
	reader    *ringbuf.Reader
	eventsCh  chan HTTPEvent
	done      chan struct{}
	closeOnce sync.Once

	// hpackMu protects hpackDecoders.
	hpackMu       sync.Mutex
	hpackDecoders map[uint64]*hpack.Decoder // keyed by ConnID (SSL* pointer)
}

// New loads the pre-compiled BPF object, creates the collection, attaches
// uprobes to all discovered TLS libraries, and starts the ring-buffer
// consumer goroutine.
//
// Returns ErrUnsupported when:
//   - the kernel does not support BPF ring buffers (< 5.8)
//   - the process lacks CAP_BPF + CAP_PERFMON
//   - no supported TLS libraries can be found on the system
func New() (Tracer, error) {
	if len(bpfObject) == 0 {
		return nil, fmt.Errorf("%w: BPF object not embedded (run go generate)", ErrUnsupported)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		return nil, fmt.Errorf("%w: parse BPF spec: %v", ErrUnsupported, err)
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("%w: load BPF objects: %v", ErrUnsupported, err)
	}

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("%w: open ring buffer reader: %v", ErrUnsupported, err)
	}

	t := &linuxTracer{
		objs:          objs,
		reader:        reader,
		eventsCh:      make(chan HTTPEvent, 256),
		done:          make(chan struct{}),
		hpackDecoders: make(map[uint64]*hpack.Decoder),
	}

	if err := t.attachLibraryProbes(); err != nil {
		t.release()
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}

	go t.readLoop()
	return t, nil
}

// attachLibraryProbes attaches SSL_write and gnutls_record_send uprobes to
// every shared library instance found under standard Linux library paths.
func (t *linuxTracer) attachLibraryProbes() error {
	var attached int

	if t.objs.ProbeSSLWrite != nil {
		n := t.attachUprobes(t.objs.ProbeSSLWrite, sslLibPaths(), "SSL_write")
		attached += n
	}

	if t.objs.ProbeGnuTLSSend != nil {
		// GnuTLS failures are non-fatal; many systems don't have it.
		_ = t.attachUprobes(t.objs.ProbeGnuTLSSend, gnutlsLibPaths(), "gnutls_record_send")
	}

	if attached == 0 {
		return errors.New("no SSL/TLS libraries found (install libssl-dev / openssl)")
	}
	return nil
}

// attachUprobes resolves each glob pattern in paths to actual library files,
// deduplicates symlinks, and attaches a uprobe for the given symbol.
// Returns the number of successful attachments.
func (t *linuxTracer) attachUprobes(prog *ebpf.Program, patterns []string, symbol string) int {
	seen := make(map[string]bool)
	var count int

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			continue
		}
		for _, p := range matches {
			real, err := filepath.EvalSymlinks(p)
			if err != nil {
				real = p
			}
			if seen[real] {
				continue
			}
			seen[real] = true

			ex, err := link.OpenExecutable(real)
			if err != nil {
				continue
			}
			l, err := ex.Uprobe(symbol, prog, nil)
			if err != nil {
				continue
			}
			t.links = append(t.links, l)
			count++
		}
	}
	return count
}

// AttachGoTLS attaches a uprobe to Go's crypto/tls.(*Conn).Write in the
// executable at exePath. This handles Go binaries that bypass OpenSSL.
func (t *linuxTracer) AttachGoTLS(exePath string) error {
	if t.objs.ProbeGoTLSWrite == nil {
		return errors.New("go_tls_write BPF program not available")
	}

	symbol, err := findGoTLSSymbol(exePath)
	if err != nil {
		return fmt.Errorf("find Go TLS symbol: %w", err)
	}

	ex, err := link.OpenExecutable(exePath)
	if err != nil {
		return fmt.Errorf("open executable: %w", err)
	}

	l, err := ex.Uprobe(symbol, t.objs.ProbeGoTLSWrite, nil)
	if err != nil {
		return fmt.Errorf("attach uprobe %s: %w", symbol, err)
	}

	t.mu.Lock()
	t.links = append(t.links, l)
	t.mu.Unlock()
	return nil
}

// AddPID adds a PID to the eBPF pid_filter map.
func (t *linuxTracer) AddPID(pid uint32) error {
	val := uint8(1)
	return t.objs.PidFilter.Put(pid, val)
}

// RemovePID removes a PID from the eBPF pid_filter map.
func (t *linuxTracer) RemovePID(pid uint32) error {
	return t.objs.PidFilter.Delete(pid)
}

// SetTraceAll sets or clears FLAG_TRACE_ALL in the BPF config map.
func (t *linuxTracer) SetTraceAll(enabled bool) error {
	key := uint32(0)
	val := uint8(0)
	if enabled {
		val = flagTraceAll
	}
	return t.objs.ConfigFlags.Put(key, val)
}

// Events returns the channel of parsed HTTPEvents.
func (t *linuxTracer) Events() <-chan HTTPEvent {
	return t.eventsCh
}

// Close stops the event loop and releases all eBPF resources.
func (t *linuxTracer) Close() error {
	t.closeOnce.Do(func() {
		close(t.done)
		_ = t.reader.Close()
		t.release()
	})
	return nil
}

func (t *linuxTracer) release() {
	for _, l := range t.links {
		l.Close()
	}
	t.objs.Close()
}

// hpackDecoderFor returns (creating if needed) the per-connection HPACK
// decoder for the given connID.  The decoder is seeded with a 4096-byte
// dynamic table limit which matches curl / browsers defaults.
func (t *linuxTracer) hpackDecoderFor(connID uint64) *hpack.Decoder {
	t.hpackMu.Lock()
	defer t.hpackMu.Unlock()
	if dec, ok := t.hpackDecoders[connID]; ok {
		return dec
	}
	dec := hpack.NewDecoder(4096, nil)
	t.hpackDecoders[connID] = dec
	return dec
}

// removeHPACKDecoder releases the HPACK decoder for connID (call when the
// TLS connection closes).  Currently unused from the uprobe layer (we have
// no SSL_free hook), but exposed for future use.
func (t *linuxTracer) removeHPACKDecoder(connID uint64) {
	t.hpackMu.Lock()
	delete(t.hpackDecoders, connID)
	t.hpackMu.Unlock()
}

// readLoop consumes records from the BPF ring buffer, parses each one as an
// ssl_event, attempts HTTP/1.x then HTTP/2 parsing, and delivers events to
// eventsCh.
func (t *linuxTracer) readLoop() {
	defer close(t.eventsCh)

	for {
		record, err := t.reader.Read()
		if err != nil {
			// Reader was closed — normal shutdown path.
			return
		}

		ev := decodeEvent(record.RawSample)
		if ev == nil {
			continue
		}

		payload := ev.Buf[:ev.Len]

		// Fast path: HTTP/1.x plain-text request.
		method, path, host, ok := ParseHTTPRequest(payload)
		if !ok && IsHTTP2(payload) {
			// Slow path: HTTP/2 binary framing — use per-connection HPACK decoder.
			dec := t.hpackDecoderFor(ev.ConnID)
			method, path, host, ok = ParseHTTP2Frames(payload, dec)
		}

		if !ok {
			continue
		}

		select {
		case t.eventsCh <- HTTPEvent{
			PID:    ev.PID,
			Method: method,
			Path:   path,
			Host:   host,
			Source: Source(ev.Source),
		}:
		case <-t.done:
			return
		default:
			// Drop if consumer is slow; ring buffer absorbs bursts.
		}
	}
}

// decodeEvent parses raw ring-buffer bytes into an sslEvent using
// little-endian byte order (all supported platforms are LE).
//
// Wire layout (matches ssl_trace.c struct ssl_event):
//
//	[0:4]   PID     uint32 LE
//	[4:8]   Len     uint32 LE
//	[8]     Source  uint8
//	[9:16]  Pad     [7]uint8
//	[16:24] ConnID  uint64 LE
//	[24:]   Buf     [maxBufSize]byte
func decodeEvent(data []byte) *sslEvent {
	const headerSize = 4 + 4 + 1 + 7 + 8 // PID(4)+Len(4)+Source(1)+Pad(7)+ConnID(8) = 24
	if len(data) < headerSize {
		return nil
	}

	ev := &sslEvent{}
	ev.PID = binary.LittleEndian.Uint32(data[0:4])
	ev.Len = binary.LittleEndian.Uint32(data[4:8])
	ev.Source = data[8]
	// data[9:16] = pad, skip
	ev.ConnID = binary.LittleEndian.Uint64(data[16:24])

	if ev.Len > maxBufSize {
		ev.Len = maxBufSize
	}
	const payloadStart = 24
	if len(data) <= payloadStart {
		return nil
	}
	available := uint32(len(data) - payloadStart)
	capLen := ev.Len
	if capLen > available {
		capLen = available
	}
	copy(ev.Buf[:capLen], data[payloadStart:payloadStart+int(capLen)])
	ev.Len = capLen
	return ev
}

// sslLibPaths returns glob patterns for libssl.so across common Linux distros.
func sslLibPaths() []string {
	return []string{
		// Debian / Ubuntu (amd64 + arm64)
		"/usr/lib/x86_64-linux-gnu/libssl.so*",
		"/usr/lib/aarch64-linux-gnu/libssl.so*",
		"/lib/x86_64-linux-gnu/libssl.so*",
		"/lib/aarch64-linux-gnu/libssl.so*",
		// RHEL / Fedora / Amazon Linux
		"/usr/lib64/libssl.so*",
		// Alpine / musl (static or pkgs)
		"/usr/lib/libssl.so*",
		"/lib/libssl.so*",
		// Custom / OpenSSL compiled from source
		"/usr/local/lib/libssl.so*",
		"/usr/local/lib64/libssl.so*",
	}
}

// gnutlsLibPaths returns glob patterns for libgnutls.so.
func gnutlsLibPaths() []string {
	return []string{
		"/usr/lib/x86_64-linux-gnu/libgnutls.so*",
		"/usr/lib/aarch64-linux-gnu/libgnutls.so*",
		"/lib/x86_64-linux-gnu/libgnutls.so*",
		"/usr/lib64/libgnutls.so*",
		"/usr/lib/libgnutls.so*",
	}
}

// findGoTLSSymbol searches the binary at exePath for Go's crypto/tls write symbol.
// Returns the first symbol name matching the known mangling patterns.
func findGoTLSSymbol(exePath string) (string, error) {
	candidates := []string{
		"crypto/tls.(*Conn).Write",
		"crypto_2ftls.(*Conn).Write",
	}
	data, err := os.ReadFile(exePath)
	if err != nil {
		return "", fmt.Errorf("read executable: %w", err)
	}
	for _, c := range candidates {
		if bytes.Contains(data, []byte(c)) {
			return c, nil
		}
	}
	return "", errors.New("crypto/tls.(*Conn).Write symbol not found in binary")
}

// PidDescendants returns all PIDs that are direct or transitive children of
// rootPID by walking /proc/<pid>/task/<tid>/children.
// Exported so callers in engine_linux.go can use it.
func PidDescendants(rootPID uint32) map[uint32]struct{} {
	result := map[uint32]struct{}{rootPID: {}}
	addChildren(rootPID, result)
	return result
}

func addChildren(pid uint32, result map[uint32]struct{}) {
	path := fmt.Sprintf("/proc/%d/task/%d/children", pid, pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, field := range strings.Fields(string(data)) {
		v, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			continue
		}
		child := uint32(v)
		if _, seen := result[child]; !seen {
			result[child] = struct{}{}
			addChildren(child, result)
		}
	}
}
