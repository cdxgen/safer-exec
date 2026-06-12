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
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
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
	// Programs — HTTP tracing (mandatory)
	ProbeSSLWrite   *ebpf.Program `ebpf:"probe_ssl_write"`
	ProbeSSLWriteEx *ebpf.Program `ebpf:"probe_ssl_write_ex"`
	ProbeGnuTLSSend *ebpf.Program `ebpf:"probe_gnutls_send"`
	ProbeGoTLSWrite *ebpf.Program `ebpf:"probe_go_tls_write"`
	// Programs — cipher tracing (optional, may be nil if not compiled into BPF object)
	ProbeSSLCipher     *ebpf.Program `ebpf:"probe_ssl_cipher,optional"`
	ProbeSSLCipherName *ebpf.Program `ebpf:"probe_ssl_cipher_name,optional"`
	ProbeSSLCipherBits *ebpf.Program `ebpf:"probe_ssl_cipher_bits,optional"`
	ProbeSSLVersion    *ebpf.Program `ebpf:"probe_ssl_version,optional"`
	ProbeGnuCipherName *ebpf.Program `ebpf:"probe_gnutls_cipher_name,optional"`

	ProbeSSLCipherEntry     *ebpf.Program `ebpf:"probe_ssl_cipher_entry,optional"`
	ProbeSSLCipherNameEntry *ebpf.Program `ebpf:"probe_ssl_cipher_name_entry,optional"`
	ProbeSSLCipherBitsEntry *ebpf.Program `ebpf:"probe_ssl_cipher_bits_entry,optional"`
	ProbeSSLVersionEntry    *ebpf.Program `ebpf:"probe_ssl_version_entry,optional"`
	ProbeLibcReadEntry      *ebpf.Program `ebpf:"probe_libc_read_entry,optional"`
	ProbeLibcReadReturn     *ebpf.Program `ebpf:"probe_libc_read_return,optional"`

	// Programs — unified socket-level tracepoints and crypto uprobes
	TraceSysEnterRead     *ebpf.Program `ebpf:"trace_sys_enter_read,optional"`
	TraceSysExitRead      *ebpf.Program `ebpf:"trace_sys_exit_read,optional"`
	TraceSysEnterWrite    *ebpf.Program `ebpf:"trace_sys_enter_write,optional"`
	TraceSysExitWrite     *ebpf.Program `ebpf:"trace_sys_exit_write,optional"`
	TraceSysEnterSendto   *ebpf.Program `ebpf:"trace_sys_enter_sendto,optional"`
	TraceSysExitSendto    *ebpf.Program `ebpf:"trace_sys_exit_sendto,optional"`
	TraceSysEnterRecvfrom *ebpf.Program `ebpf:"trace_sys_enter_recvfrom,optional"`
	TraceSysExitRecvfrom  *ebpf.Program `ebpf:"trace_sys_exit_recvfrom,optional"`
	TraceSysEnterConnect  *ebpf.Program `ebpf:"trace_sys_enter_connect,optional"`
	ProbeCryptoMD5        *ebpf.Program `ebpf:"probe_crypto_md5,optional"`
	ProbeCryptoSHA1       *ebpf.Program `ebpf:"probe_crypto_sha1,optional"`
	ProbeCryptoSHA256     *ebpf.Program `ebpf:"probe_crypto_sha256,optional"`
	ProbeCryptoSHA512     *ebpf.Program `ebpf:"probe_crypto_sha512,optional"`
	ProbeCryptoAESEnc     *ebpf.Program `ebpf:"probe_crypto_aes_enc,optional"`
	ProbeCryptoAESDec     *ebpf.Program `ebpf:"probe_crypto_aes_dec,optional"`
	ProbeCryptoSHA224     *ebpf.Program `ebpf:"probe_crypto_sha224,optional"`
	ProbeCryptoSHA384     *ebpf.Program `ebpf:"probe_crypto_sha384,optional"`

	// Programs — LSM BPF hooks
	BprmCheckSecurity *ebpf.Program `ebpf:"bprm_check_security,optional"`
	FileOpen          *ebpf.Program `ebpf:"file_open,optional"`

	// Maps — HTTP tracing (mandatory)
	Events      *ebpf.Map `ebpf:"events"`
	PidFilter   *ebpf.Map `ebpf:"pid_filter"`
	ConfigFlags *ebpf.Map `ebpf:"config_flags"`
	// Maps — cipher tracing (optional)
	CipherEvents *ebpf.Map `ebpf:"cipher_events,optional"`
}

func (o *bpfObjects) Close() {
	if o.ProbeSSLWrite != nil {
		o.ProbeSSLWrite.Close()
	}
	if o.ProbeSSLWriteEx != nil {
		o.ProbeSSLWriteEx.Close()
	}
	if o.ProbeGnuTLSSend != nil {
		o.ProbeGnuTLSSend.Close()
	}
	if o.ProbeGoTLSWrite != nil {
		o.ProbeGoTLSWrite.Close()
	}
	if o.ProbeSSLCipher != nil {
		o.ProbeSSLCipher.Close()
	}
	if o.ProbeSSLCipherName != nil {
		o.ProbeSSLCipherName.Close()
	}
	if o.ProbeSSLCipherBits != nil {
		o.ProbeSSLCipherBits.Close()
	}
	if o.ProbeSSLVersion != nil {
		o.ProbeSSLVersion.Close()
	}
	if o.ProbeGnuCipherName != nil {
		o.ProbeGnuCipherName.Close()
	}
	if o.ProbeSSLCipherEntry != nil {
		o.ProbeSSLCipherEntry.Close()
	}
	if o.ProbeSSLCipherNameEntry != nil {
		o.ProbeSSLCipherNameEntry.Close()
	}
	if o.ProbeSSLCipherBitsEntry != nil {
		o.ProbeSSLCipherBitsEntry.Close()
	}
	if o.ProbeSSLVersionEntry != nil {
		o.ProbeSSLVersionEntry.Close()
	}
	if o.ProbeLibcReadEntry != nil {
		o.ProbeLibcReadEntry.Close()
	}
	if o.ProbeLibcReadReturn != nil {
		o.ProbeLibcReadReturn.Close()
	}
	if o.TraceSysEnterRead != nil {
		o.TraceSysEnterRead.Close()
	}
	if o.TraceSysExitRead != nil {
		o.TraceSysExitRead.Close()
	}
	if o.TraceSysEnterWrite != nil {
		o.TraceSysEnterWrite.Close()
	}
	if o.TraceSysExitWrite != nil {
		o.TraceSysExitWrite.Close()
	}
	if o.TraceSysEnterSendto != nil {
		o.TraceSysEnterSendto.Close()
	}
	if o.TraceSysExitSendto != nil {
		o.TraceSysExitSendto.Close()
	}
	if o.TraceSysEnterRecvfrom != nil {
		o.TraceSysEnterRecvfrom.Close()
	}
	if o.TraceSysExitRecvfrom != nil {
		o.TraceSysExitRecvfrom.Close()
	}
	if o.TraceSysEnterConnect != nil {
		o.TraceSysEnterConnect.Close()
	}
	if o.ProbeCryptoMD5 != nil {
		o.ProbeCryptoMD5.Close()
	}
	if o.ProbeCryptoSHA1 != nil {
		o.ProbeCryptoSHA1.Close()
	}
	if o.ProbeCryptoSHA256 != nil {
		o.ProbeCryptoSHA256.Close()
	}
	if o.ProbeCryptoSHA512 != nil {
		o.ProbeCryptoSHA512.Close()
	}
	if o.ProbeCryptoAESEnc != nil {
		o.ProbeCryptoAESEnc.Close()
	}
	if o.ProbeCryptoAESDec != nil {
		o.ProbeCryptoAESDec.Close()
	}
	if o.ProbeCryptoSHA224 != nil {
		o.ProbeCryptoSHA224.Close()
	}
	if o.ProbeCryptoSHA384 != nil {
		o.ProbeCryptoSHA384.Close()
	}
	if o.BprmCheckSecurity != nil {
		o.BprmCheckSecurity.Close()
	}
	if o.FileOpen != nil {
		o.FileOpen.Close()
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
	if o.CipherEvents != nil {
		o.CipherEvents.Close()
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

	// Cipher tracing (opt-in)
	cryptoEnabled bool
	cipherReader  *ringbuf.Reader
	cipherDone    chan struct{}
	// cipherMu protects cipherMap, cipherNameMap, and cipherPtrToConn.
	cipherMu        sync.Mutex
	cipherMap       map[uint64]CipherResult // connID (ssl*) → CipherResult
	cipherNameMap   map[uint32]string       // cipher* (lower 32 bits) → cipher name
	cipherPtrToConn map[uint32]uint64       // cipher* (lower 32 bits) → ssl* (conn_id)

	// Detected libraries
	detectedLibs []CryptoLibraryInfo
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
	// Remove memlock limit for BPF map creation
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: httptrace: warning: failed to remove memlock limit: %v\n", err)
	}

	if len(bpfObject) == 0 {
		return nil, fmt.Errorf("%w: BPF object not embedded (run go generate)", ErrUnsupported)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		return nil, fmt.Errorf("%w: parse BPF spec: %v", ErrUnsupported, err)
	}

	var coll *ebpf.Collection
	coll, err = ebpf.NewCollection(spec)
	if err != nil {
		// The cipher uretprobes (probe_ssl_cipher etc.) may be rejected by the BPF verifier
		// on older kernels (e.g. 5.15) that don't allow reading function arguments in uretprobe
		// context. Strip them and retry so HTTP tracing still works on those kernels.
		fmt.Fprintf(os.Stderr, "safer-exec: httptrace: BPF load failed (%v); retrying without cipher programs\n", err)
		for _, name := range []string{
			"probe_ssl_cipher", "probe_ssl_cipher_name", "probe_ssl_cipher_bits",
			"probe_ssl_version", "probe_gnutls_cipher_name",
			"probe_ssl_cipher_entry", "probe_ssl_cipher_name_entry",
			"probe_ssl_cipher_bits_entry", "probe_ssl_version_entry",
			"probe_libc_read_entry", "probe_libc_read_return",
			"trace_sys_enter_read", "trace_sys_exit_read",
			"trace_sys_enter_write", "trace_sys_exit_write",
			"trace_sys_enter_sendto", "trace_sys_exit_sendto",
			"trace_sys_enter_recvfrom", "trace_sys_exit_recvfrom",
			"trace_sys_enter_connect", "probe_crypto_md5",
			"probe_crypto_sha1", "probe_crypto_sha256",
			"probe_crypto_sha512", "probe_crypto_aes_enc",
			"probe_crypto_aes_dec", "probe_crypto_sha224",
			"probe_crypto_sha384", "bprm_check_security",
			"file_open",
		} {
			delete(spec.Programs, name)
		}
		delete(spec.Maps, "cipher_events")
		var err2 error
		coll, err2 = ebpf.NewCollection(spec)
		if err2 != nil {
			return nil, fmt.Errorf("%w: load BPF objects: %v", ErrUnsupported, err2)
		}
	}

	var objs bpfObjects
	objs.ProbeSSLWrite = coll.Programs["probe_ssl_write"]
	objs.ProbeSSLWriteEx = coll.Programs["probe_ssl_write_ex"]
	objs.ProbeGnuTLSSend = coll.Programs["probe_gnutls_send"]
	objs.ProbeGoTLSWrite = coll.Programs["probe_go_tls_write"]
	objs.ProbeSSLCipher = coll.Programs["probe_ssl_cipher"]
	objs.ProbeSSLCipherName = coll.Programs["probe_ssl_cipher_name"]
	objs.ProbeSSLCipherBits = coll.Programs["probe_ssl_cipher_bits"]
	objs.ProbeSSLVersion = coll.Programs["probe_ssl_version"]
	objs.ProbeGnuCipherName = coll.Programs["probe_gnutls_cipher_name"]
	objs.ProbeSSLCipherEntry = coll.Programs["probe_ssl_cipher_entry"]
	objs.ProbeSSLCipherNameEntry = coll.Programs["probe_ssl_cipher_name_entry"]
	objs.ProbeSSLCipherBitsEntry = coll.Programs["probe_ssl_cipher_bits_entry"]
	objs.ProbeSSLVersionEntry = coll.Programs["probe_ssl_version_entry"]
	objs.ProbeLibcReadEntry = coll.Programs["probe_libc_read_entry"]
	objs.ProbeLibcReadReturn = coll.Programs["probe_libc_read_return"]
	objs.TraceSysEnterRead = coll.Programs["trace_sys_enter_read"]
	objs.TraceSysExitRead = coll.Programs["trace_sys_exit_read"]
	objs.TraceSysEnterWrite = coll.Programs["trace_sys_enter_write"]
	objs.TraceSysExitWrite = coll.Programs["trace_sys_exit_write"]
	objs.TraceSysEnterSendto = coll.Programs["trace_sys_enter_sendto"]
	objs.TraceSysExitSendto = coll.Programs["trace_sys_exit_sendto"]
	objs.TraceSysEnterRecvfrom = coll.Programs["trace_sys_enter_recvfrom"]
	objs.TraceSysExitRecvfrom = coll.Programs["trace_sys_exit_recvfrom"]
	objs.TraceSysEnterConnect = coll.Programs["trace_sys_enter_connect"]
	objs.ProbeCryptoMD5 = coll.Programs["probe_crypto_md5"]
	objs.ProbeCryptoSHA1 = coll.Programs["probe_crypto_sha1"]
	objs.ProbeCryptoSHA256 = coll.Programs["probe_crypto_sha256"]
	objs.ProbeCryptoSHA512 = coll.Programs["probe_crypto_sha512"]
	objs.ProbeCryptoAESEnc = coll.Programs["probe_crypto_aes_enc"]
	objs.ProbeCryptoAESDec = coll.Programs["probe_crypto_aes_dec"]
	objs.ProbeCryptoSHA224 = coll.Programs["probe_crypto_sha224"]
	objs.ProbeCryptoSHA384 = coll.Programs["probe_crypto_sha384"]
	objs.BprmCheckSecurity = coll.Programs["bprm_check_security"]
	objs.FileOpen = coll.Programs["file_open"]
	objs.Events = coll.Maps["events"]
	objs.PidFilter = coll.Maps["pid_filter"]
	objs.ConfigFlags = coll.Maps["config_flags"]
	objs.CipherEvents = coll.Maps["cipher_events"]

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("%w: open ring buffer reader: %v", ErrUnsupported, err)
	}

	t := &linuxTracer{
		objs:            objs,
		reader:          reader,
		eventsCh:        make(chan HTTPEvent, 256),
		done:            make(chan struct{}),
		hpackDecoders:   make(map[uint64]*hpack.Decoder),
		cipherMap:       make(map[uint64]CipherResult),
		cipherNameMap:   make(map[uint32]string),
		cipherPtrToConn: make(map[uint32]uint64),
	}

	if err := t.attachLibraryProbes(); err != nil {
		t.release()
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}

	go t.readLoop()
	return t, nil
}

// attachLibraryProbes attaches SSL_write, SSL_write_ex and gnutls_record_send uprobes to
// every shared library instance found under standard Linux library paths.
// Also records detected library paths for later version extraction.
func (t *linuxTracer) attachLibraryProbes() error {
	var attached int

	if t.objs.ProbeSSLWrite != nil {
		n, libs := t.attachUprobesWithLibs(t.objs.ProbeSSLWrite, sslLibPaths(), "SSL_write")
		attached += n
		for _, lib := range libs {
			t.detectedLibs = append(t.detectedLibs, CryptoLibraryInfo{
				Name:   "OpenSSL",
				Path:   lib.path,
				Source: "ebpf_uprobe",
			})
		}
	}

	if t.objs.ProbeSSLWriteEx != nil {
		n, libs := t.attachUprobesWithLibs(t.objs.ProbeSSLWriteEx, sslLibPaths(), "SSL_write_ex")
		attached += n
		for _, lib := range libs {
			t.detectedLibs = append(t.detectedLibs, CryptoLibraryInfo{
				Name:   "OpenSSL",
				Path:   lib.path,
				Source: "ebpf_uprobe",
			})
		}
	}

	if t.objs.ProbeGnuTLSSend != nil {
		n, libs := t.attachUprobesWithLibs(t.objs.ProbeGnuTLSSend, gnutlsLibPaths(), "gnutls_record_send")
		_ = n
		for _, lib := range libs {
			t.detectedLibs = append(t.detectedLibs, CryptoLibraryInfo{
				Name:   "GnuTLS",
				Path:   lib.path,
				Source: "ebpf_uprobe",
			})
		}
	}

	if attached == 0 {
		return errors.New("no SSL/TLS libraries found (install libssl-dev / openssl)")
	}

	// Deduplicate detected libraries
	t.detectedLibs = deduplicateLibs(t.detectedLibs)
	// Fill in versions from library paths
	for i := range t.detectedLibs {
		t.detectedLibs[i].Version = extractLibVersion(t.detectedLibs[i].Path, t.detectedLibs[i].Name)
	}

	return nil
}

type libAttachment struct {
	path string
}

// attachUprobesWithLibs is like attachUprobes but also returns info about the libraries that were attached.
func (t *linuxTracer) attachUprobesWithLibs(prog *ebpf.Program, patterns []string, symbol string) (int, []libAttachment) {
	seen := make(map[string]bool)
	var count int
	var libs []libAttachment

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
			fmt.Fprintf(os.Stderr, "safer-exec: httptrace: attached to %s symbol %s\n", real, symbol)
			t.links = append(t.links, l)
			count++
			libs = append(libs, libAttachment{path: real})
		}
	}
	return count, libs
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
			fmt.Fprintf(os.Stderr, "safer-exec: httptrace: attached to %s symbol %s\n", real, symbol)
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

// AttachStaticOpenSSL attaches the OpenSSL SSL_write/SSL_write_ex uprobes directly to the target executable.
// This handles statically linked binaries (like Node.js or Python builds) that export the OpenSSL symbol.
func (t *linuxTracer) AttachStaticOpenSSL(exePath string) error {
	ex, err := link.OpenExecutable(exePath)
	if err != nil {
		return fmt.Errorf("open target executable: %w", err)
	}

	var attached bool

	if t.objs.ProbeSSLWrite != nil {
		l, err := ex.Uprobe("SSL_write", t.objs.ProbeSSLWrite, nil)
		if err == nil {
			fmt.Fprintf(os.Stderr, "safer-exec: httptrace: AttachStaticOpenSSL attached to %s symbol SSL_write\n", exePath)
			t.mu.Lock()
			t.links = append(t.links, l)
			t.mu.Unlock()
			attached = true
		}
	}

	if t.objs.ProbeSSLWriteEx != nil {
		l, err := ex.Uprobe("SSL_write_ex", t.objs.ProbeSSLWriteEx, nil)
		if err == nil {
			fmt.Fprintf(os.Stderr, "safer-exec: httptrace: AttachStaticOpenSSL attached to %s symbol SSL_write_ex\n", exePath)
			t.mu.Lock()
			t.links = append(t.links, l)
			t.mu.Unlock()
			attached = true
		}
	}

	if !attached {
		return fmt.Errorf("could not attach static SSL_write or SSL_write_ex uprobe to %s", exePath)
	}

	// If crypto tracing is enabled, also attach cipher uprobes and uretprobes directly to the target executable.
	if t.cryptoEnabled {
		if t.objs.ProbeSSLCipherEntry != nil {
			if l, err := ex.Uprobe("SSL_get_current_cipher", t.objs.ProbeSSLCipherEntry, nil); err == nil {
				fmt.Fprintf(os.Stderr, "safer-exec: httptrace: AttachStaticOpenSSL attached to %s symbol SSL_get_current_cipher (entry)\n", exePath)
				t.mu.Lock()
				t.links = append(t.links, l)
				t.mu.Unlock()
			}
		}
		if t.objs.ProbeSSLCipher != nil {
			if l, err := ex.Uretprobe("SSL_get_current_cipher", t.objs.ProbeSSLCipher, nil); err == nil {
				fmt.Fprintf(os.Stderr, "safer-exec: httptrace: AttachStaticOpenSSL attached to %s symbol SSL_get_current_cipher\n", exePath)
				t.mu.Lock()
				t.links = append(t.links, l)
				t.mu.Unlock()
			}
		}

		if t.objs.ProbeSSLCipherNameEntry != nil {
			if l, err := ex.Uprobe("SSL_CIPHER_get_name", t.objs.ProbeSSLCipherNameEntry, nil); err == nil {
				fmt.Fprintf(os.Stderr, "safer-exec: httptrace: AttachStaticOpenSSL attached to %s symbol SSL_CIPHER_get_name (entry)\n", exePath)
				t.mu.Lock()
				t.links = append(t.links, l)
				t.mu.Unlock()
			}
		}
		if t.objs.ProbeSSLCipherName != nil {
			if l, err := ex.Uretprobe("SSL_CIPHER_get_name", t.objs.ProbeSSLCipherName, nil); err == nil {
				fmt.Fprintf(os.Stderr, "safer-exec: httptrace: AttachStaticOpenSSL attached to %s symbol SSL_CIPHER_get_name\n", exePath)
				t.mu.Lock()
				t.links = append(t.links, l)
				t.mu.Unlock()
			}
		}

		if t.objs.ProbeSSLCipherBitsEntry != nil {
			if l, err := ex.Uprobe("SSL_CIPHER_get_bits", t.objs.ProbeSSLCipherBitsEntry, nil); err == nil {
				fmt.Fprintf(os.Stderr, "safer-exec: httptrace: AttachStaticOpenSSL attached to %s symbol SSL_CIPHER_get_bits (entry)\n", exePath)
				t.mu.Lock()
				t.links = append(t.links, l)
				t.mu.Unlock()
			}
		}
		if t.objs.ProbeSSLCipherBits != nil {
			if l, err := ex.Uretprobe("SSL_CIPHER_get_bits", t.objs.ProbeSSLCipherBits, nil); err == nil {
				fmt.Fprintf(os.Stderr, "safer-exec: httptrace: AttachStaticOpenSSL attached to %s symbol SSL_CIPHER_get_bits\n", exePath)
				t.mu.Lock()
				t.links = append(t.links, l)
				t.mu.Unlock()
			}
		}

		if t.objs.ProbeSSLVersionEntry != nil {
			if l, err := ex.Uprobe("SSL_get_version", t.objs.ProbeSSLVersionEntry, nil); err == nil {
				fmt.Fprintf(os.Stderr, "safer-exec: httptrace: AttachStaticOpenSSL attached to %s symbol SSL_get_version (entry)\n", exePath)
				t.mu.Lock()
				t.links = append(t.links, l)
				t.mu.Unlock()
			}
		}
		if t.objs.ProbeSSLVersion != nil {
			if l, err := ex.Uretprobe("SSL_get_version", t.objs.ProbeSSLVersion, nil); err == nil {
				fmt.Fprintf(os.Stderr, "safer-exec: httptrace: AttachStaticOpenSSL attached to %s symbol SSL_get_version\n", exePath)
				t.mu.Lock()
				t.links = append(t.links, l)
				t.mu.Unlock()
			}
		}
	}

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
		if t.cipherReader != nil {
			_ = t.cipherReader.Close()
		}
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
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			// Transient read error (e.g. on custom kernels) — retry.
			time.Sleep(10 * time.Millisecond)
			continue
		}

		ev := decodeEvent(record.RawSample)
		if ev == nil {
			continue
		}

		payload := ev.Buf[:ev.Len]

		// Fast path: HTTP/1.x plain-text request.
		method, path, query, host, body, ok := ParseHTTPRequest(payload)
		if !ok && IsHTTP2(payload) {
			// Slow path: HTTP/2 binary framing — use per-connection HPACK decoder.
			dec := t.hpackDecoderFor(ev.ConnID)
			var q string
			method, path, q, host, ok = ParseHTTP2Frames(payload, dec)
			query = q
		}

		if !ok {
			continue
		}

		parsedHost := host
		port := 443
		if h, pStr, err := net.SplitHostPort(host); err == nil {
			parsedHost = h
			if p, err := strconv.Atoi(pStr); err == nil {
				port = p
			}
		}

		// Look up cipher info for this connection if crypto tracing is enabled
		var cipherName, tlsVersion, cryptoLib, cryptoLibVersion string
		var cipherSuite uint16
		var cipherBits int
		if t.cryptoEnabled {
			if cipherResult, ok := t.CipherForConnID(ev.ConnID, ev.PID); ok {
				cipherName = cipherResult.Name
				cipherSuite = cipherResult.IANAID
				tlsVersion = cipherResult.Protocol
				cipherBits = cipherResult.Bits
			}
			// Determine crypto library from source
			switch Source(ev.Source) {
			case SourceSSLWrite:
				cryptoLib = "OpenSSL"
			case SourceGoTLS:
				cryptoLib = "Go crypto/tls"
			case SourceGnuTLSSend:
				cryptoLib = "GnuTLS"
			}
			for _, lib := range t.detectedLibs {
				if lib.Name == cryptoLib {
					cryptoLibVersion = lib.Version
					break
				}
			}
		}

		select {
		case t.eventsCh <- HTTPEvent{
			PID:                  ev.PID,
			Method:               method,
			Path:                 path,
			Host:                 parsedHost,
			Protocol:             "https",
			Port:                 port,
			Query:                query,
			Body:                 body,
			Source:               Source(ev.Source),
			CipherName:           cipherName,
			CipherSuite:          cipherSuite,
			TLSVersion:           tlsVersion,
			CipherBits:           cipherBits,
			CryptoLibrary:        cryptoLib,
			CryptoLibraryVersion: cryptoLibVersion,
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

// libcLibPaths returns glob patterns for libc.so across common Linux distros.
func libcLibPaths() []string {
	return []string{
		"/usr/lib/x86_64-linux-gnu/libc.so*",
		"/usr/lib/aarch64-linux-gnu/libc.so*",
		"/lib/x86_64-linux-gnu/libc.so*",
		"/lib/aarch64-linux-gnu/libc.so*",
		"/usr/lib64/libc.so*",
		"/usr/lib/libc.so*",
		"/lib/libc.so*",
		"/lib64/libc.so*",
	}
}

// EnableCryptoTracing attaches eBPF uretprobes to TLS cipher negotiation
// functions and starts the cipher event consumer goroutine.
func (t *linuxTracer) EnableCryptoTracing() error {
	if t.objs.CipherEvents == nil {
		return errors.New("cipher tracing BPF programs not compiled into binary (rebuild BPF objects)")
	}

	reader, err := ringbuf.NewReader(t.objs.CipherEvents)
	if err != nil {
		return fmt.Errorf("open cipher ring buffer: %w", err)
	}

	t.cipherReader = reader
	t.cipherDone = make(chan struct{})
	t.cryptoEnabled = true

	// Attach cipher probes to OpenSSL libraries
	sslPaths := sslLibPaths()
	if t.objs.ProbeSSLCipherEntry != nil {
		t.attachLibProbe(t.objs.ProbeSSLCipherEntry, "SSL_get_current_cipher", false, sslPaths)
	}
	if t.objs.ProbeSSLCipher != nil {
		t.attachLibProbe(t.objs.ProbeSSLCipher, "SSL_get_current_cipher", true, sslPaths)
	}

	if t.objs.ProbeSSLCipherNameEntry != nil {
		t.attachLibProbe(t.objs.ProbeSSLCipherNameEntry, "SSL_CIPHER_get_name", false, sslPaths)
	}
	if t.objs.ProbeSSLCipherName != nil {
		t.attachLibProbe(t.objs.ProbeSSLCipherName, "SSL_CIPHER_get_name", true, sslPaths)
	}

	if t.objs.ProbeSSLCipherBitsEntry != nil {
		t.attachLibProbe(t.objs.ProbeSSLCipherBitsEntry, "SSL_CIPHER_get_bits", false, sslPaths)
	}
	if t.objs.ProbeSSLCipherBits != nil {
		t.attachLibProbe(t.objs.ProbeSSLCipherBits, "SSL_CIPHER_get_bits", true, sslPaths)
	}

	if t.objs.ProbeSSLVersionEntry != nil {
		t.attachLibProbe(t.objs.ProbeSSLVersionEntry, "SSL_get_version", false, sslPaths)
	}
	if t.objs.ProbeSSLVersion != nil {
		t.attachLibProbe(t.objs.ProbeSSLVersion, "SSL_get_version", true, sslPaths)
	}

	gnutlsPaths := gnutlsLibPaths()
	if t.objs.ProbeGnuCipherName != nil {
		t.attachLibProbe(t.objs.ProbeGnuCipherName, "gnutls_cipher_suite_get_name", true, gnutlsPaths)
	}

	// Fallback raw handshake tracing: attach to libc read, recv, recvfrom
	libcPaths := libcLibPaths()
	if t.objs.ProbeLibcReadEntry != nil {
		t.attachLibProbe(t.objs.ProbeLibcReadEntry, "read", false, libcPaths)
		t.attachLibProbe(t.objs.ProbeLibcReadEntry, "recv", false, libcPaths)
		t.attachLibProbe(t.objs.ProbeLibcReadEntry, "recvfrom", false, libcPaths)
	}
	if t.objs.ProbeLibcReadReturn != nil {
		t.attachLibProbe(t.objs.ProbeLibcReadReturn, "read", true, libcPaths)
		t.attachLibProbe(t.objs.ProbeLibcReadReturn, "recv", true, libcPaths)
		t.attachLibProbe(t.objs.ProbeLibcReadReturn, "recvfrom", true, libcPaths)
	}

	// Attach unified socket tracepoints if compiled
	if t.objs.TraceSysEnterRead != nil {
		l, err := link.Tracepoint("syscalls", "sys_enter_read", t.objs.TraceSysEnterRead, nil)
		if err == nil {
			t.mu.Lock()
			t.links = append(t.links, l)
			t.mu.Unlock()
		}
	}
	if t.objs.TraceSysExitRead != nil {
		l, err := link.Tracepoint("syscalls", "sys_exit_read", t.objs.TraceSysExitRead, nil)
		if err == nil {
			t.mu.Lock()
			t.links = append(t.links, l)
			t.mu.Unlock()
		}
	}
	if t.objs.TraceSysEnterWrite != nil {
		l, err := link.Tracepoint("syscalls", "sys_enter_write", t.objs.TraceSysEnterWrite, nil)
		if err == nil {
			t.mu.Lock()
			t.links = append(t.links, l)
			t.mu.Unlock()
		}
	}
	if t.objs.TraceSysExitWrite != nil {
		l, err := link.Tracepoint("syscalls", "sys_exit_write", t.objs.TraceSysExitWrite, nil)
		if err == nil {
			t.mu.Lock()
			t.links = append(t.links, l)
			t.mu.Unlock()
		}
	}
	if t.objs.TraceSysEnterSendto != nil {
		l, err := link.Tracepoint("syscalls", "sys_enter_sendto", t.objs.TraceSysEnterSendto, nil)
		if err == nil {
			t.mu.Lock()
			t.links = append(t.links, l)
			t.mu.Unlock()
		}
	}
	if t.objs.TraceSysExitSendto != nil {
		l, err := link.Tracepoint("syscalls", "sys_exit_sendto", t.objs.TraceSysExitSendto, nil)
		if err == nil {
			t.mu.Lock()
			t.links = append(t.links, l)
			t.mu.Unlock()
		}
	}
	if t.objs.TraceSysEnterRecvfrom != nil {
		l, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", t.objs.TraceSysEnterRecvfrom, nil)
		if err == nil {
			t.mu.Lock()
			t.links = append(t.links, l)
			t.mu.Unlock()
		}
	}
	if t.objs.TraceSysExitRecvfrom != nil {
		l, err := link.Tracepoint("syscalls", "sys_exit_recvfrom", t.objs.TraceSysExitRecvfrom, nil)
		if err == nil {
			t.mu.Lock()
			t.links = append(t.links, l)
			t.mu.Unlock()
		}
	}
	if t.objs.TraceSysEnterConnect != nil {
		l, err := link.Tracepoint("syscalls", "sys_enter_connect", t.objs.TraceSysEnterConnect, nil)
		if err == nil {
			t.mu.Lock()
			t.links = append(t.links, l)
			t.mu.Unlock()
		}
	}

	// Attach cryptographic operations uprobes
	libcryptoPaths := []string{
		"/usr/lib/x86_64-linux-gnu/libcrypto.so*",
		"/usr/lib/aarch64-linux-gnu/libcrypto.so*",
		"/lib/x86_64-linux-gnu/libcrypto.so*",
		"/lib/aarch64-linux-gnu/libcrypto.so*",
		"/usr/lib64/libcrypto.so*",
		"/usr/lib/libcrypto.so*",
		"/lib/libcrypto.so*",
	}
	if t.objs.ProbeCryptoMD5 != nil {
		t.attachLibProbe(t.objs.ProbeCryptoMD5, "MD5_Init", false, libcryptoPaths)
	}
	if t.objs.ProbeCryptoSHA1 != nil {
		t.attachLibProbe(t.objs.ProbeCryptoSHA1, "SHA1_Init", false, libcryptoPaths)
	}
	if t.objs.ProbeCryptoSHA256 != nil {
		t.attachLibProbe(t.objs.ProbeCryptoSHA256, "SHA256_Init", false, libcryptoPaths)
	}
	if t.objs.ProbeCryptoSHA512 != nil {
		t.attachLibProbe(t.objs.ProbeCryptoSHA512, "SHA512_Init", false, libcryptoPaths)
	}
	if t.objs.ProbeCryptoAESEnc != nil {
		t.attachLibProbe(t.objs.ProbeCryptoAESEnc, "AES_set_encrypt_key", false, libcryptoPaths)
	}
	if t.objs.ProbeCryptoAESDec != nil {
		t.attachLibProbe(t.objs.ProbeCryptoAESDec, "AES_set_decrypt_key", false, libcryptoPaths)
	}
	if t.objs.ProbeCryptoSHA224 != nil {
		t.attachLibProbe(t.objs.ProbeCryptoSHA224, "SHA224_Init", false, libcryptoPaths)
	}
	if t.objs.ProbeCryptoSHA384 != nil {
		t.attachLibProbe(t.objs.ProbeCryptoSHA384, "SHA384_Init", false, libcryptoPaths)
	}

	// Attach LSM BPF programs if compiled and supported by the kernel
	if t.objs.BprmCheckSecurity != nil {
		l, err := link.AttachLSM(link.LSMOptions{
			Program: t.objs.BprmCheckSecurity,
		})
		if err == nil {
			t.mu.Lock()
			t.links = append(t.links, l)
			t.mu.Unlock()
		} else {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: failed to attach LSM bprm_check_security: %v\n", err)
		}
	}
	if t.objs.FileOpen != nil {
		l, err := link.AttachLSM(link.LSMOptions{
			Program: t.objs.FileOpen,
		})
		if err == nil {
			t.mu.Lock()
			t.links = append(t.links, l)
			t.mu.Unlock()
		} else {
			fmt.Fprintf(os.Stderr, "safer-exec: warning: failed to attach LSM file_open: %v\n", err)
		}
	}

	go t.readCipherLoop()
	return nil
}

// attachLibProbe probes known library paths and attaches
// a uprobe or uretprobe for the given symbol name. Non-fatal on failure.
func (t *linuxTracer) attachLibProbe(prog *ebpf.Program, symbol string, isUret bool, paths []string) {
	seen := make(map[string]bool)
	for _, pattern := range paths {
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
			var l link.Link
			if isUret {
				l, err = ex.Uretprobe(symbol, prog, nil)
			} else {
				l, err = ex.Uprobe(symbol, prog, nil)
			}
			if err != nil {
				continue
			}
			fmt.Fprintf(os.Stderr, "safer-exec: httptrace: cipher probe attached to %s symbol %s (uret=%v)\n", real, symbol, isUret)
			t.mu.Lock()
			t.links = append(t.links, l)
			t.mu.Unlock()
		}
	}
}

// DetectedLibraries returns the list of crypto libraries detected during probing.
func (t *linuxTracer) DetectedLibraries() []CryptoLibraryInfo {
	return t.detectedLibs
}

// CipherForConnID returns the CipherResult for the given connID, if available.
// Also supports PID-based fallback matching if the connID is not found.
// Called when building HTTPEvents to attach cipher info.
func (t *linuxTracer) CipherForConnID(connID uint64, pid uint32) (CipherResult, bool) {
	t.cipherMu.Lock()
	defer t.cipherMu.Unlock()
	if r, ok := t.cipherMap[connID]; ok {
		return r, ok
	}
	r, ok := t.cipherMap[uint64(pid)]
	return r, ok
}

// extractLibVersion extracts a library version from a shared library path.
//
// Examples:
//
//	"/usr/lib/x86_64-linux-gnu/libssl.so.3"    → "3"
//	"/usr/lib/x86_64-linux-gnu/libssl.so.1.1"  → "1.1"
//	"/usr/lib/libgnutls.so.30.41.1"             → "30.41.1"
func extractLibVersion(path, libName string) string {
	base := filepath.Base(path)

	// Strip known library prefixes
	prefixes := []string{"libssl.so.", "libcrypto.so.", "libgnutls.so.", "libnss3.so.", "libnssutil3.so."}
	for _, prefix := range prefixes {
		if strings.HasPrefix(base, prefix) {
			ver := strings.TrimPrefix(base, prefix)
			if ver != "" && ver != base {
				return ver
			}
		}
	}

	// Generic: try to find a version-like suffix
	ext := filepath.Ext(base)
	if ext != "" && strings.HasPrefix(ext, ".so.") {
		return ext[4:]
	}

	// For version-less symlinks like "libssl.so" → "libssl.so.3",
	// resolve the symlink and try again
	if real, err := filepath.EvalSymlinks(path); err == nil && real != path {
		return extractLibVersion(real, libName)
	}

	return ""
}

// deduplicateLibs removes duplicate crypto library entries (by path).
func deduplicateLibs(libs []CryptoLibraryInfo) []CryptoLibraryInfo {
	seen := make(map[string]bool)
	var result []CryptoLibraryInfo
	for _, lib := range libs {
		if !seen[lib.Path] {
			seen[lib.Path] = true
			result = append(result, lib)
		}
	}
	return result
}

// cipherEvent mirrors the BPF-side struct cipher_event (ssl_trace.c).
//
// The C compiler inserts 4 bytes of implicit alignment padding between the
// explicit __u32 pad field and __u64 conn_id (which needs 8-byte alignment).
// Actual wire layout (verified with offsetof):
//
//	offset  0: PID     uint32
//	offset  4: Source  uint32
//	offset  8: Pad     uint32  (explicit C field)
//	offset 12: [4 bytes implicit alignment padding]
//	offset 16: ConnID  uint64
//	offset 24: Bits    uint32
//	offset 28: Name    [128]byte
//	total: 160 bytes (including trailing alignment padding)
const maxCipherName = 128

type cipherEventRaw struct {
	PID    uint32
	Source uint32
	Pad    uint32
	ConnID uint64
	Bits   uint32
	Name   [maxCipherName]byte
}

// readCipherLoop consumes cipher events from the cipher ring buffer.
func (t *linuxTracer) readCipherLoop() {
	defer close(t.cipherDone)

	if t.cipherReader == nil {
		return
	}

	for {
		record, err := t.cipherReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		ev := decodeCipherEvent(record.RawSample)
		if ev == nil {
			continue
		}

		name := strings.TrimRight(string(ev.Name[:]), "\x00")

		t.cipherMu.Lock()

		if ev.Source == 3 { // SOURCE_RAW_HANDSHAKE
			payload := ev.Name[:]
			if int(ev.Bits) < len(payload) {
				payload = ev.Name[:ev.Bits]
			}
			if ev.Bits == 0xffff { // Connect event
				if len(payload) >= 7 {
					family := payload[0]
					var ip net.IP
					var port uint16
					if family == 4 && len(payload) >= 7 {
						ip = net.IP(payload[1:5])
						port = binary.LittleEndian.Uint16(payload[5:7])
					} else if family == 6 && len(payload) >= 19 {
						ip = net.IP(payload[1:17])
						port = binary.LittleEndian.Uint16(payload[17:19])
					}
					if ip != nil {
						// Store connection info keyed by process PID or a temp mapping
						// This allows resolving hostname via SNI or mapping later.
						// For now, write it as a pseudo cipher map entry
						cr := CipherResult{
							ConnID:   ev.ConnID,
							Name:     "TCP_ESTABLISHED",
							IANAName: ip.String() + ":" + strconv.Itoa(int(port)),
							PID:      ev.PID,
						}
						t.cipherMap[ev.ConnID] = cr
						t.cipherMap[uint64(ev.PID)] = cr
					}
				}
				t.cipherMu.Unlock()
				continue
			}

			if len(payload) >= 44 {
				if payload[0] == 0x16 && payload[1] == 0x03 {
					hsType := payload[5]
					if hsType == 0x01 { // ClientHello (SNI check)
						if host, ok := parseSNI(payload); ok {
							cr := t.cipherMap[ev.ConnID]
							cr.ConnID = ev.ConnID
							cr.PID = ev.PID
							cr.Protocol = host // Store SNI hostname in Protocol field temporarily
							t.cipherMap[ev.ConnID] = cr
							t.cipherMap[uint64(ev.PID)] = cr
						}
					} else if hsType == 0x02 { // ServerHello
						sessionIDLen := int(payload[43])
						if 44+sessionIDLen+2 <= len(payload) {
							cipherID := binary.BigEndian.Uint16(payload[44+sessionIDLen : 46+sessionIDLen])
							if cname, ok := CipherNameByID(cipherID); ok {
								cr := t.cipherMap[ev.ConnID]
								cr.ConnID = ev.ConnID
								cr.Name = cname
								cr.PID = ev.PID
								cr.IANAName = IANACipherName(cname)
								cr.IANAID = cipherID
								cr.Protocol = "TLSv1.2"
								if payload[9] == 3 && payload[10] == 4 {
									cr.Protocol = "TLSv1.3"
								}
								cr.Bits = 256

								t.cipherMap[ev.ConnID] = cr
								t.cipherMap[uint64(ev.PID)] = cr
							}
						}
					}
				}
			}
			t.cipherMu.Unlock()
			continue
		}

		if ev.Source == 4 { // SOURCE_CRYPTO_OP
			algoMap := map[uint32][2]string{
				1: {"digest", "MD5"},
				2: {"digest", "SHA-1"},
				3: {"digest", "SHA-256"},
				4: {"digest", "SHA-512"},
				5: {"encrypt", "AES"},
				6: {"decrypt", "AES"},
				7: {"digest", "SHA-224"},
				8: {"digest", "SHA-384"},
			}
			if info, ok := algoMap[ev.Bits]; ok {
				// Record this cryptographic operation
				cr := CipherResult{
					ConnID:   0,
					Name:     info[1], // Algorithm
					IANAName: info[0], // Type
					Bits:     int(ev.Bits),
					PID:      ev.PID,
				}
				// We can store it in cipherMap using a special key format or a dedicated channel.
				// Since we also read cipher events, we can treat this as a special cipherMap entry.
				t.cipherMap[uint64(ev.PID)] = cr
			}
			t.cipherMu.Unlock()
			continue
		}

		// SSL_get_current_cipher: connID = ssl*, bits field carries cipher*
		// SSL_CIPHER_get_name: connID lower32 = cipher*, name field carries cipher name
		// SSL_CIPHER_get_bits: connID lower32 = cipher*, bits field carries secret bits
		// SSL_get_version: connID = ssl*, name field carries version string

		if ev.Bits > 0 && name == "" && ev.ConnID > 0xFFFFFFFF {
			// SSL_get_current_cipher: connID = ssl*, bits = lower32(cipher*)
			// Record cipher* → ssl* so SSL_CIPHER_get_name events can resolve ssl*.
			cipherPtr := uint32(ev.Bits)
			t.cipherPtrToConn[cipherPtr] = ev.ConnID
			// If SSL_CIPHER_get_name already arrived (out-of-order), apply it now.
			if cipherName, ok := t.cipherNameMap[cipherPtr]; ok {
				cr := t.cipherMap[ev.ConnID]
				cr.ConnID = ev.ConnID
				cr.PID = ev.PID
				cr.Name = cipherName
				cr.IANAName = IANACipherName(cipherName)
				cr.IANAID, _ = knownIANACipher(cipherName)
				t.cipherMap[ev.ConnID] = cr
				t.cipherMap[uint64(ev.PID)] = cr
			} else {
				// Store placeholder — name will be filled when SSL_CIPHER_get_name fires.
				t.cipherMap[ev.ConnID] = CipherResult{ConnID: ev.ConnID, PID: ev.PID}
			}
		} else if ev.Bits > 0 && name == "" && ev.ConnID < 0x100000000 {
			// SSL_CIPHER_get_bits: connID lower32 = cipher*, bits = secret bits
			cipherPtr := uint32(ev.ConnID)
			if sslConn, ok := t.cipherPtrToConn[cipherPtr]; ok {
				if cr, ok := t.cipherMap[sslConn]; ok {
					cr.Bits = int(ev.Bits)
					t.cipherMap[sslConn] = cr
					t.cipherMap[uint64(ev.PID)] = cr
				}
			}
		} else if name != "" && ev.Bits == 0 && ev.ConnID > 0xFFFFFFFF {
			// SSL_get_version: connID = ssl*, name = version string
			if existing, ok := t.cipherMap[ev.ConnID]; ok {
				existing.Protocol = name
				t.cipherMap[ev.ConnID] = existing
				t.cipherMap[uint64(ev.PID)] = existing
			}
		} else if name != "" && ev.ConnID < 0x100000000 {
			// SSL_CIPHER_get_name: connID lower32 = cipher*, name = cipher suite string
			cipherPtr := uint32(ev.ConnID)
			t.cipherNameMap[cipherPtr] = name
			if sslConn, ok := t.cipherPtrToConn[cipherPtr]; ok {
				// ssl* is known — update the cipher result directly.
				cr := t.cipherMap[sslConn]
				cr.ConnID = sslConn
				cr.Name = name
				cr.IANAName = IANACipherName(name)
				cr.IANAID, _ = knownIANACipher(name)
				t.cipherMap[sslConn] = cr
				t.cipherMap[uint64(ev.PID)] = cr
			}
			// If ssl* not yet known, cipherNameMap entry will be picked up when
			// SSL_get_current_cipher fires (handled in the first branch above).
		}

		t.cipherMu.Unlock()
	}
}

// parseSNI parses Server Name Indication (SNI) hostname from the raw TLS ClientHello payload.
// Logic details based on RFC 5246 (TLSv1.2) & RFC 8446 (TLSv1.3) Record/Handshake structures:
// 1. Check TLS Record Header (payload[0:5]):
//   - payload[0] == 0x16 (Handshake record type)
//   - payload[1:3] == 0x03 0x01 / 0x03 0x03 (TLS Protocol Version)
//
// 2. Check Handshake Header:
//   - payload[5] == 0x01 (Handshake Type: ClientHello)
//
// 3. Skip Client Version (2 bytes) + Random (32 bytes) starting at byte 6 -> sessionID offset is 43.
// 4. Parse Session ID (payload[43] is length, skip it).
// 5. Parse Cipher Suites (length is 2 bytes at current offset, skip suite list bytes).
// 6. Parse Compression Methods (length is 1 byte, skip compress byte).
// 7. Parse Extensions:
//   - Read Extensions block length (2 bytes).
//   - Iterate through extensions: each has Type (2 bytes) + Length (2 bytes) + Value.
//   - Look for Extension Type 0x0000 (Server Name Indication, RFC 6066 Section 3).
//   - Extract the Server Name list: read Server Name Type (0x00 for HostName), read HostName length (2 bytes), and return the name string.
func parseSNI(payload []byte) (string, bool) {
	if len(payload) < 44 {
		return "", false
	}
	if payload[0] != 0x16 || payload[1] != 0x03 {
		return "", false
	}
	if payload[5] != 0x01 {
		return "", false
	}

	curr := 43
	if curr >= len(payload) {
		return "", false
	}
	sessionIDLen := int(payload[curr])
	curr += 1 + sessionIDLen

	if curr+2 > len(payload) {
		return "", false
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[curr : curr+2]))
	curr += 2 + cipherSuitesLen

	if curr+1 > len(payload) {
		return "", false
	}
	compressionLen := int(payload[curr])
	curr += 1 + compressionLen

	if curr+2 > len(payload) {
		return "", false
	}
	extensionsLen := int(binary.BigEndian.Uint16(payload[curr : curr+2]))
	curr += 2

	end := curr + extensionsLen
	if end > len(payload) {
		end = len(payload)
	}

	for curr+4 <= end {
		extType := binary.BigEndian.Uint16(payload[curr : curr+2])
		extLen := int(binary.BigEndian.Uint16(payload[curr+2 : curr+4]))
		curr += 4

		if curr+extLen > end {
			break
		}

		if extType == 0 { // SNI
			sniData := payload[curr : curr+extLen]
			if len(sniData) >= 5 {
				if sniData[2] == 0 { // HostName type
					nameLen := int(binary.BigEndian.Uint16(sniData[3:5]))
					if 5+nameLen <= len(sniData) {
						return string(sniData[5 : 5+nameLen]), true
					}
				}
			}
		}
		curr += extLen
	}
	return "", false
}

func decodeCipherEvent(data []byte) *cipherEventRaw {
	// Offsets match the actual C struct layout including implicit alignment padding.
	// See cipherEventRaw comment for the full layout.
	const headerSize = 28 // PID(4)+Source(4)+Pad(4)+[align4]+ConnID(8)+Bits(4) = 28
	if len(data) < headerSize {
		return nil
	}

	ev := &cipherEventRaw{}
	ev.PID = binary.LittleEndian.Uint32(data[0:4])
	ev.Source = binary.LittleEndian.Uint32(data[4:8])
	// data[8:12]  = explicit __u32 pad field (ignored)
	// data[12:16] = 4 bytes implicit alignment padding (ignored)
	ev.ConnID = binary.LittleEndian.Uint64(data[16:24])
	ev.Bits = binary.LittleEndian.Uint32(data[24:28])

	copyStart := headerSize
	copyLen := len(data) - copyStart
	if copyLen > maxCipherName {
		copyLen = maxCipherName
	}
	copy(ev.Name[:copyLen], data[copyStart:copyStart+copyLen])

	return ev
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
