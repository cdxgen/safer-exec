// Package tlsobserve reads the cleartext part of a TLS handshake from the two
// byte streams of a connection, without terminating or altering it.
//
// The egress proxy forwards CONNECT tunnels byte for byte. The hello messages
// at the start of a tunnel are not encrypted, even in TLS 1.3, so the proxy
// can learn the negotiated protocol version, cipher suite and key-exchange
// group (including post-quantum hybrids) of every connection the workload
// makes, whatever TLS library it uses. Up to TLS 1.2 the server's certificate
// and key exchange are cleartext too, so the whole certificate chain the
// server presented is recorded; TLS 1.3 encrypts them.
package tlsobserve

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Handshake is what the cleartext part of one handshake revealed.
type Handshake struct {
	// ServerName is the SNI the client sent; with ECH it is the outer name.
	ServerName string
	// ECH is set when the client offered Encrypted Client Hello.
	ECH bool
	// Version is the negotiated protocol version (0x0303 for TLS 1.2).
	Version uint16
	// CipherSuite is the negotiated IANA cipher suite.
	CipherSuite uint16
	// Group is the key-exchange group: the TLS 1.3 key share, or the named
	// curve of a TLS 1.2 ECDHE key exchange. Zero when unknown.
	Group uint16
	// DHBits is the prime size of a TLS 1.2 finite-field DHE key exchange.
	DHBits int
	// ServerKey describes the server certificate's public key ("RSA-2048",
	// "ECDSA-P256", "Ed25519"); only TLS 1.2 and earlier send it in clear.
	ServerKey string
	// CertSignature is the server certificate's signature algorithm
	// ("SHA256-RSA"); TLS 1.2 and earlier only.
	CertSignature string
	// Chain records every certificate of the server's TLS ≤ 1.2 certificate
	// list, the leaf first. TLS 1.3 encrypts the Certificate message, so no
	// chain is recorded there. It is what the server sent, unverified.
	Chain []ChainCert
	// Resumed is set when a TLS 1.2 session was resumed (no certificate or
	// key exchange is sent).
	Resumed bool
}

// ChainCert is one certificate of the chain a server presented. The hashes
// identify the certificate for SPKI-based distrust lists: SpkiSha256 is the
// same digest Go's crypto/x509 distrust list (CVE-2026-111943) and SPKI pins
// are built from. config.CertChainEntry has the same fields in the same
// order, so the proxy converts one into the other directly.
type ChainCert struct {
	// Name is the certificate's component name: the subject CN, else the
	// first subject RDN value, else the subject string.
	Name string
	// Subject and Issuer are the RFC 4514 name strings.
	Subject, Issuer string
	// SerialNumber is lowercase hex without leading zeros.
	SerialNumber string
	// NotValidBefore and NotValidAfter are the validity bounds, RFC 3339 UTC.
	NotValidBefore, NotValidAfter string
	// Version is the X.509 version (1 or 3).
	Version int
	// SignatureAlgorithm is the issuer's signature algorithm ("SHA256-RSA",
	// "ML-DSA-65"), or its dotted OID when unknown; SignatureAlgorithmOid is
	// that OID.
	SignatureAlgorithm, SignatureAlgorithmOid string
	// CertSha256 is SHA-256 over the whole DER certificate; SpkiSha256 over
	// the DER SubjectPublicKeyInfo. Both lowercase hex.
	CertSha256, SpkiSha256 string
	// SpkiSha256Base64 is the SPKI digest in the RFC 7469 pin-sha256 form
	// (standard base64 of the same digest bytes).
	SpkiSha256Base64 string
	// KeyName names the public key algorithm and size ("RSA-2048",
	// "ECDSA-P256", "Ed25519", "ML-DSA-65"), or is its dotted OID when
	// unknown; KeyBits is its size in bits, 0 for post-quantum and unknown
	// keys; KeyAlgorithmOid is the SubjectPublicKeyInfo algorithm OID.
	KeyName         string
	KeyBits         int
	KeyAlgorithmOid string
	// IsCA is the basicConstraints CA flag. SelfSigned means the subject and
	// issuer DER are equal and the self-signature verifies;
	// SelfSignedUnverified that the signature could not be checked and the
	// certificate counts as self-signed because it is self-issued.
	IsCA, SelfSigned, SelfSignedUnverified bool
}

const (
	recordHandshake        = 22
	recordChangeCipherSpec = 20
	recordAlert            = 21
	recordHeaderLen        = 5
	maxRecordLen           = 1<<14 + 2048

	msgClientHello       = 1
	msgServerHello       = 2
	msgCertificate       = 11
	msgServerKeyExchange = 12
	msgServerHelloDone   = 14

	extServerName        = 0
	extSupportedVersions = 43
	extKeyShare          = 51
	extECH               = 0xfe0d

	// Byte budgets per direction; a handshake that has not produced its
	// cleartext messages by then is not followed further.
	clientLimit = 64 << 10
	serverLimit = 256 << 10

	// Bounds on the server certificate chain: at most maxChainCerts entries
	// and maxChainBytes of certificate bytes are turned into chain records.
	maxChainCerts = 10
	maxChainBytes = 64 << 10
)

// helloRetryRandom is the ServerHello random of a TLS 1.3 HelloRetryRequest.
var helloRetryRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// Observer follows one connection. Feed it the client-to-server bytes through
// Client and the server-to-client bytes through Server; both writers always
// accept the whole buffer, so they can sit in an io.TeeReader without ever
// disturbing the connection.
type Observer struct {
	mu       sync.Mutex
	hs       Handshake
	client   stream
	server   stream
	hello    bool // a (final) ServerHello was parsed
	certSeen bool
	reported bool
	onDone   func(Handshake)
}

// New returns an Observer that calls onDone once, as soon as the handshake's
// cleartext part has been read (or when Close is called after a ServerHello).
func New(onDone func(Handshake)) *Observer {
	o := &Observer{onDone: onDone}
	o.client.limit = clientLimit
	o.server.limit = serverLimit
	return o
}

// Client returns the writer for bytes the client sends.
func (o *Observer) Client() io.Writer { return writerFunc(o.feedClient) }

// Server returns the writer for bytes the server sends.
func (o *Observer) Server() io.Writer { return writerFunc(o.feedServer) }

type writerFunc func([]byte)

func (f writerFunc) Write(p []byte) (int, error) {
	f(p)
	return len(p), nil
}

// ClientReader wraps the reader of client-to-server bytes and ServerReader
// the reader of server-to-client bytes. The bytes pass through unchanged and
// are shown to the observer until the cleartext part of the handshake is
// over; after that io.Copy reads the underlying reader directly, so it can
// use the platform's zero-copy paths for the rest of the connection.
func (o *Observer) ClientReader(r io.Reader) io.Reader {
	return &tee{r: r, feed: o.feedClient, done: func() bool { return o.streamDone(&o.client) }}
}

// ServerReader: see ClientReader.
func (o *Observer) ServerReader(r io.Reader) io.Reader {
	return &tee{r: r, feed: o.feedServer, done: func() bool { return o.streamDone(&o.server) }}
}

func (o *Observer) streamDone(s *stream) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return s.done
}

type tee struct {
	r    io.Reader
	feed func([]byte)
	done func() bool
}

func (t *tee) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 && !t.done() {
		t.feed(p[:n])
	}
	return n, err
}

// WriteTo lets io.Copy hand the connection back to the underlying reader
// once the observer has nothing left to read.
func (t *tee) WriteTo(dst io.Writer) (int64, error) {
	buf := make([]byte, 32<<10)
	var total int64
	for !t.done() {
		n, err := t.r.Read(buf)
		if n > 0 {
			t.feed(buf[:n])
			w, werr := dst.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total, werr
			}
			if w < n {
				return total, io.ErrShortWrite
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
	n, err := io.Copy(dst, t.r)
	return total + n, err
}

// Close reports a handshake whose ServerHello was seen but whose remaining
// cleartext messages never arrived.
func (o *Observer) Close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.finish()
}

// Result returns the handshake and whether a ServerHello was seen.
func (o *Observer) Result() (Handshake, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.hs, o.hello
}

func (o *Observer) finish() {
	if o.reported || !o.hello {
		return
	}
	o.reported = true
	o.client.stop()
	o.server.stop()
	if o.onDone != nil {
		o.onDone(o.hs)
	}
}

func (o *Observer) feedClient(p []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.client.feed(p, o.clientMessage)
}

func (o *Observer) feedServer(p []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.server.feed(p, o.serverMessage)
	if o.server.ccs && o.hello && o.hs.Version < 0x0304 && !o.certSeen {
		o.hs.Resumed = true
	}
	if o.server.done {
		o.finish()
	}
}

// clientMessage handles one client handshake message; it returns false to
// stop following the client stream.
func (o *Observer) clientMessage(typ byte, body []byte) bool {
	if typ != msgClientHello {
		return false
	}
	parseClientHello(body, &o.hs)
	// A HelloRetryRequest makes the client send a second ClientHello, which
	// carries nothing new for the report.
	return false
}

// serverMessage handles one server handshake message; it returns false once
// nothing more is cleartext.
func (o *Observer) serverMessage(typ byte, body []byte) bool {
	switch typ {
	case msgServerHello:
		retry, ok := parseServerHello(body, &o.hs)
		if !ok {
			return false
		}
		if retry {
			// The real ServerHello follows the client's second hello, after
			// a middlebox-compatibility ChangeCipherSpec that, in TLS 1.3,
			// does not end the cleartext.
			o.server.ccsIgnored = true
			return true
		}
		o.hello = true
		if o.hs.Version >= 0x0304 {
			return false // everything after the ServerHello is encrypted
		}
		return true
	case msgCertificate:
		if o.hello {
			o.certSeen = true
			parseCertificate(body, &o.hs)
		}
		return true
	case msgServerKeyExchange:
		if o.hello {
			parseServerKeyExchange(body, &o.hs)
		}
		return true
	case msgServerHelloDone:
		return false
	}
	return true
}

// stream reassembles the handshake messages of one direction.
type stream struct {
	limit   int
	seen    int
	records []byte // unparsed record bytes
	msgs    []byte // handshake message bytes not yet complete
	done    bool
	ccs     bool
	// ccsIgnored is set after a TLS 1.3 HelloRetryRequest, whose
	// ChangeCipherSpec is only for middlebox compatibility.
	ccsIgnored bool
}

func (s *stream) stop() {
	s.done = true
	s.records = nil
	s.msgs = nil
}

func (s *stream) feed(p []byte, handle func(byte, []byte) bool) {
	if s.done {
		return
	}
	s.seen += len(p)
	if s.seen > s.limit {
		s.stop()
		return
	}
	s.records = append(s.records, p...)
	for !s.done && len(s.records) >= recordHeaderLen {
		typ := s.records[0]
		n := int(binary.BigEndian.Uint16(s.records[3:5]))
		if s.records[1] != 3 || n > maxRecordLen {
			s.stop() // not TLS
			return
		}
		if len(s.records) < recordHeaderLen+n {
			return
		}
		frag := s.records[recordHeaderLen : recordHeaderLen+n]
		s.records = s.records[recordHeaderLen+n:]
		switch typ {
		case recordHandshake:
			if s.ccs {
				s.stop() // an encrypted Finished
				return
			}
			s.msgs = append(s.msgs, frag...)
			for !s.done && len(s.msgs) >= 4 {
				ml := int(s.msgs[1])<<16 | int(s.msgs[2])<<8 | int(s.msgs[3])
				if ml > s.limit {
					s.stop()
					return
				}
				if len(s.msgs) < 4+ml {
					break
				}
				mt, body := s.msgs[0], s.msgs[4:4+ml]
				s.msgs = s.msgs[4+ml:]
				if !handle(mt, body) {
					s.stop()
					return
				}
			}
		case recordChangeCipherSpec:
			// TLS 1.3 middlebox compatibility sends one before encrypted
			// records; in TLS 1.2 everything after it is encrypted.
			if !s.ccsIgnored {
				s.ccs = true
			}
		case recordAlert:
			s.stop()
		default:
			s.stop() // application data: the cleartext part is over
		}
	}
}

// reader is a minimal cursor over handshake message bytes.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) n(k int) []byte {
	if r.bad || len(r.b) < k {
		r.bad = true
		return nil
	}
	v := r.b[:k]
	r.b = r.b[k:]
	return v
}

func (r *reader) u8() int {
	v := r.n(1)
	if v == nil {
		return 0
	}
	return int(v[0])
}

func (r *reader) u16() int {
	v := r.n(2)
	if v == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(v))
}

func (r *reader) u24() int {
	v := r.n(3)
	if v == nil {
		return 0
	}
	return int(v[0])<<16 | int(v[1])<<8 | int(v[2])
}

func (r *reader) vec8() []byte  { return r.n(r.u8()) }
func (r *reader) vec16() []byte { return r.n(r.u16()) }

// extensions calls fn for each extension in a vec16-prefixed block.
func extensions(r *reader, fn func(typ int, data []byte)) {
	if len(r.b) == 0 {
		return
	}
	block := reader{b: r.vec16()}
	for !block.bad && len(block.b) >= 4 {
		typ := block.u16()
		data := block.vec16()
		if block.bad {
			return
		}
		fn(typ, data)
	}
}

func parseClientHello(body []byte, hs *Handshake) {
	r := reader{b: body}
	r.n(2)    // legacy_version
	r.n(32)   // random
	r.vec8()  // session id
	r.vec16() // cipher suites
	r.vec8()  // compression methods
	if r.bad {
		return
	}
	extensions(&r, func(typ int, data []byte) {
		switch typ {
		case extServerName:
			list := reader{b: data}
			names := reader{b: list.vec16()}
			for !names.bad && len(names.b) > 0 {
				kind := names.u8()
				name := names.vec16()
				if kind == 0 && !names.bad && hs.ServerName == "" {
					hs.ServerName = string(name)
				}
			}
		case extECH:
			hs.ECH = true
		}
	})
}

// parseServerHello fills in the version, suite and (TLS 1.3) group. It
// reports whether the message was a HelloRetryRequest and whether it parsed.
func parseServerHello(body []byte, hs *Handshake) (retry, ok bool) {
	r := reader{b: body}
	legacy := r.u16()
	random := r.n(32)
	r.vec8() // session id
	suite := r.u16()
	r.u8() // compression
	if r.bad {
		return false, false
	}
	retry = bytes.Equal(random, helloRetryRandom)
	version := uint16(legacy)
	var group uint16
	extensions(&r, func(typ int, data []byte) {
		switch typ {
		case extSupportedVersions:
			if len(data) == 2 {
				version = binary.BigEndian.Uint16(data)
			}
		case extKeyShare:
			if len(data) >= 2 {
				group = binary.BigEndian.Uint16(data)
			}
		}
	})
	hs.CipherSuite = uint16(suite)
	hs.Version = version
	if group != 0 {
		hs.Group = group
	}
	return retry, true
}

// parseCertificate walks a TLS ≤ 1.2 Certificate message (RFC 5246 §7.4.2):
// a 3-byte-length-prefixed certificate_list of 3-byte-length-prefixed DER
// certificates, the server's own first. Every entry becomes a chain record
// until a bound (maxChainCerts entries, maxChainBytes of certificate bytes)
// or a malformed entry stops the walk, which keeps what already parsed. The
// first certificate also fills ServerKey and CertSignature, whatever its
// size, as it did before chains were recorded.
func parseCertificate(body []byte, hs *Handshake) {
	r := reader{b: body}
	list := reader{b: r.n(r.u24())}
	total := 0
	for len(list.b) > 0 && len(hs.Chain) < maxChainCerts {
		der := list.n(list.u24())
		if list.bad || len(der) == 0 {
			return
		}
		leaf := total == 0
		if total += len(der); total > maxChainBytes && !leaf {
			return
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return
		}
		if leaf {
			hs.CertSignature, _ = signatureAlgorithmID(cert)
			hs.ServerKey = serverKeyString(cert)
		}
		if total > maxChainBytes {
			return
		}
		hs.Chain = append(hs.Chain, chainCert(cert))
	}
}

// serverKeyString is the ServerKey form of a certificate's key: the
// publicKeyID name, except that ECDSA keys keep the curve's own name
// ("ECDSA-P-256"), as ServerKey always has.
func serverKeyString(cert *x509.Certificate) string {
	if k, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		return "ECDSA-" + k.Curve.Params().Name
	}
	name, _, _ := publicKeyID(cert)
	return name
}

// chainCert records the identity fields and hashes of one presented
// certificate.
func chainCert(cert *x509.Certificate) ChainCert {
	certSum := sha256.Sum256(cert.Raw)
	spkiSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	keyName, keyBits, keyOID := publicKeyID(cert)
	sigName, sigOID := signatureAlgorithmID(cert)
	self, unverified := selfSigned(cert)
	return ChainCert{
		Name:                  certName(cert),
		Subject:               cert.Subject.String(),
		Issuer:                cert.Issuer.String(),
		SerialNumber:          cert.SerialNumber.Text(16),
		NotValidBefore:        cert.NotBefore.UTC().Format(time.RFC3339),
		NotValidAfter:         cert.NotAfter.UTC().Format(time.RFC3339),
		Version:               cert.Version,
		SignatureAlgorithm:    sigName,
		SignatureAlgorithmOid: sigOID,
		CertSha256:            hex.EncodeToString(certSum[:]),
		SpkiSha256:            hex.EncodeToString(spkiSum[:]),
		SpkiSha256Base64:      base64.StdEncoding.EncodeToString(spkiSum[:]),
		KeyName:               keyName,
		KeyBits:               keyBits,
		KeyAlgorithmOid:       keyOID,
		IsCA:                  cert.IsCA,
		SelfSigned:            self,
		SelfSignedUnverified:  unverified,
	}
}

// selfSigned reports whether cert signed itself: its subject and issuer are
// the same name and the signature verifies under its own key. CheckSignature
// is used, not CheckSignatureFrom, which also refuses SHA-1 signatures and
// signers that are not CAs. When the signature cannot be checked (an
// algorithm this Go release does not implement, or MD5), a self-issued
// certificate — equal names, and an authority key identifier that is absent
// or equals the subject key identifier — counts as self-signed, unverified.
func selfSigned(cert *x509.Certificate) (signed, unverified bool) {
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false, false
	}
	err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err == nil {
		return true, false
	}
	var insecure x509.InsecureAlgorithmError
	if !errors.Is(err, x509.ErrUnsupportedAlgorithm) && !errors.As(err, &insecure) {
		return false, false
	}
	if len(cert.AuthorityKeyId) > 0 && !bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId) {
		return false, false
	}
	return true, true
}

// certName is the certificate's component name: the subject CN, else the
// first subject RDN value, else the subject string.
func certName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	for _, atv := range cert.Subject.Names {
		if s, ok := atv.Value.(string); ok && s != "" {
			return s
		}
	}
	return cert.Subject.String()
}

// publicKeyID names a certificate's public key the way a CBOM public-key
// component does ("RSA-2048", "ECDSA-P256", "Ed25519", "ML-DSA-65"), with
// its size in bits (0 for post-quantum and unknown keys) and the dotted OID
// of its SubjectPublicKeyInfo algorithm. Post-quantum keys are named from
// that OID, so the name does not depend on what this Go release parses; a
// key no name is known for is named by the OID itself.
func publicKeyID(cert *x509.Certificate) (name string, bits int, oid string) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err == nil {
		oid = spki.Algorithm.Algorithm.String()
	}
	if a, ok := pqAlgorithmByOID(oid); ok {
		return a.Name, 0, oid
	}
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen()), k.N.BitLen(), oid
	case *ecdsa.PublicKey:
		bits := k.Curve.Params().BitSize
		return fmt.Sprintf("ECDSA-P%d", bits), bits, oid
	case ed25519.PublicKey:
		return "Ed25519", 256, oid
	}
	if cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm || oid == "" {
		return cert.PublicKeyAlgorithm.String(), 0, oid
	}
	return oid, 0, oid
}

// signatureAlgorithmID names the algorithm a certificate is signed with
// ("SHA256-RSA", "ML-DSA-44") and returns the dotted OID of its outer
// signatureAlgorithm. As with keys, post-quantum algorithms are named from
// the OID, and an algorithm no name is known for is named by the OID.
func signatureAlgorithmID(cert *x509.Certificate) (name, oid string) {
	var c struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.Raw, &c); err == nil {
		oid = c.Algorithm.Algorithm.String()
	}
	if a, ok := pqAlgorithmByOID(oid); ok {
		return a.Name, oid
	}
	if cert.SignatureAlgorithm != x509.UnknownSignatureAlgorithm || oid == "" {
		return cert.SignatureAlgorithm.String(), oid
	}
	return oid, oid
}

func parseServerKeyExchange(body []byte, hs *Handshake) {
	kx := Suite(hs.CipherSuite).KeyExchange
	r := reader{b: body}
	switch kx {
	case "ECDHE":
		if r.u8() == 3 { // named_curve
			if g := r.u16(); !r.bad {
				hs.Group = uint16(g)
			}
		}
	case "DHE":
		p := r.vec16()
		for len(p) > 0 && p[0] == 0 {
			p = p[1:]
		}
		if !r.bad && len(p) > 0 {
			hs.DHBits = len(p) * 8
		}
	}
}

// HelloReader wraps the reader of client-to-server bytes and calls onHello
// once with the ClientHello's server name and ECH flag, as soon as the first
// ClientHello is complete. It follows only the client direction, so the egress
// proxy can compare every tunnel's SNI with its CONNECT target without the
// cost of the full Observer. Bytes pass through unchanged; a stream that is
// not TLS, or whose ClientHello exceeds the client byte budget, never calls
// onHello.
func HelloReader(r io.Reader, onHello func(serverName string, ech bool)) io.Reader {
	h := &helloWatch{onHello: onHello}
	h.s.limit = clientLimit
	return &tee{r: r, feed: h.feed, done: h.finished}
}

type helloWatch struct {
	mu      sync.Mutex
	s       stream
	onHello func(string, bool)
}

func (h *helloWatch) feed(p []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.s.feed(p, func(typ byte, body []byte) bool {
		if typ == msgClientHello {
			var hs Handshake
			parseClientHello(body, &hs)
			if h.onHello != nil {
				h.onHello(hs.ServerName, hs.ECH)
			}
		}
		return false
	})
}

func (h *helloWatch) finished() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.s.done
}
