package tlsobserve

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func certificate(t *testing.T, key any) tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "observe.test"},
		DNSNames:     []string{"observe.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	var pub any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

var (
	certOnce sync.Once
	rsaCert  tls.Certificate
	ecCert   tls.Certificate
)

func certs(t *testing.T) {
	certOnce.Do(func() {
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		rsaCert, ecCert = certificate(t, rk), certificate(t, ek)
	})
}

// handshake runs a TLS handshake through an observer that sees both
// directions, as the proxy's tunnel does, and returns what it reported.
func handshake(t *testing.T, client, server *tls.Config, chunk int) (Handshake, bool) {
	t.Helper()
	clientSide, proxyClient := net.Pipe()
	proxyServer, serverSide := net.Pipe()
	var (
		mu       sync.Mutex
		got      Handshake
		reported bool
	)
	obs := New(func(h Handshake) {
		mu.Lock()
		got, reported = h, true
		mu.Unlock()
	})
	relay := func(dst net.Conn, src net.Conn, w io.Writer) {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			for off := 0; off < n; {
				end := n
				if chunk > 0 && off+chunk < n {
					end = off + chunk
				}
				_, _ = w.Write(buf[off:end])
				if _, werr := dst.Write(buf[off:end]); werr != nil {
					return
				}
				off = end
			}
			if err != nil {
				dst.Close()
				return
			}
		}
	}
	go relay(proxyServer, proxyClient, obs.Client())
	go relay(proxyClient, proxyServer, obs.Server())

	errs := make(chan error, 2)
	tc := tls.Client(clientSide, client)
	ts := tls.Server(serverSide, server)
	go func() { errs <- tc.Handshake() }()
	go func() { errs <- ts.Handshake() }()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}
	// Exchange application data so a session ticket (TLS 1.3) or Finished
	// reaches the observer before the connection closes.
	go func() { _, _ = ts.Write([]byte("x")); ts.Close() }()
	_, _ = io.ReadAll(tc)
	tc.Close()
	obs.Close()
	mu.Lock()
	defer mu.Unlock()
	return got, reported
}

func TestTLS13HybridKeyExchange(t *testing.T) {
	certs(t)
	hs, ok := handshake(t,
		&tls.Config{InsecureSkipVerify: true, ServerName: "observe.test", CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}},
		&tls.Config{Certificates: []tls.Certificate{ecCert}}, 0)
	if !ok {
		t.Fatal("no handshake reported")
	}
	if hs.Version != 0x0304 || hs.Group != 0x11EC || hs.ServerName != "observe.test" || !Suite(hs.CipherSuite).Known {
		t.Fatalf("handshake = %+v", hs)
	}
	if hs.ServerKey != "" || hs.CertSignature != "" || hs.Chain != nil {
		t.Errorf("TLS 1.3 certificate is encrypted, yet reported: %+v", hs)
	}
	if GroupName(hs.Group) != "X25519MLKEM768" || !GroupPostQuantum(hs.Group) || GroupKeyExchange(hs.Group) != "ECDHE+ML-KEM" {
		t.Errorf("group naming: %s", GroupName(hs.Group))
	}
}

func TestTLS13HelloRetryRequest(t *testing.T) {
	certs(t)
	// The client's first key share (X25519) is not acceptable to the server,
	// which asks for P-384; the observer must follow the retry and its
	// compatibility ChangeCipherSpec to the real ServerHello.
	hs, ok := handshake(t,
		&tls.Config{InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP384}},
		&tls.Config{Certificates: []tls.Certificate{ecCert}, CurvePreferences: []tls.CurveID{tls.CurveP384}}, 0)
	if !ok || hs.Version != 0x0304 || hs.Group != 0x0018 {
		t.Fatalf("handshake = %+v (reported %v)", hs, ok)
	}
}

func TestTLS12CertificateAndKeyExchange(t *testing.T) {
	certs(t)
	for _, chunk := range []int{0, 1, 7} {
		hs, ok := handshake(t,
			&tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12},
			&tls.Config{
				Certificates:     []tls.Certificate{rsaCert},
				CipherSuites:     []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				CurvePreferences: []tls.CurveID{tls.CurveP256},
			}, chunk)
		if !ok {
			t.Fatalf("chunk %d: no handshake reported", chunk)
		}
		// The new Chain field must not change the existing fields, which all
		// come from the first certificate.
		if hs.Version != 0x0303 || hs.CipherSuite != 0xC02F || hs.Group != 0x0017 ||
			hs.ServerKey != "RSA-2048" || hs.CertSignature != "SHA256-RSA" {
			t.Fatalf("chunk %d: handshake = %+v", chunk, hs)
		}
		if len(hs.Chain) != 1 {
			t.Fatalf("chunk %d: chain = %+v, want the single presented certificate", chunk, hs.Chain)
		}
		cert, err := x509.ParseCertificate(rsaCert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(cert.Raw)
		// The certificate signs itself without being a CA: self-signed all
		// the same (CheckSignatureFrom would refuse a non-CA signer).
		if hs.Chain[0].CertSha256 != hex.EncodeToString(sum[:]) || hs.Chain[0].Name != "observe.test" ||
			!hs.Chain[0].SelfSigned || hs.Chain[0].SelfSignedUnverified || hs.Chain[0].IsCA ||
			hs.Chain[0].KeyName != "RSA-2048" || hs.Chain[0].KeyBits != 2048 || hs.Chain[0].KeyAlgorithmOid != "1.2.840.113549.1.1.1" {
			t.Fatalf("chunk %d: chain entry = %+v", chunk, hs.Chain[0])
		}
	}
}

// chainPKI builds a three-level PKI with distinct ECDSA P-256 keys: a root,
// an intermediate issued by the root, and a leaf issued by the intermediate.
func chainPKI(t *testing.T) (root, inter, leaf tls.Certificate) {
	t.Helper()
	issue := func(cn string, isCA bool, key *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) tls.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: cn},
			DNSNames:              []string{"observe.test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  isCA,
		}
		if isCA {
			tmpl.KeyUsage = x509.KeyUsageCertSign
		}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatalf("create %s: %v", cn, err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	rootKey := keygen(t)
	interKey := keygen(t)
	leafKey := keygen(t)
	root = issue("test-root-ca", true, rootKey, nil, nil)
	rootParsed, err := x509.ParseCertificate(root.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	inter = issue("test-intermediate", true, interKey, rootParsed, rootKey)
	interParsed, err := x509.ParseCertificate(inter.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	leaf = issue("test-leaf", false, leafKey, interParsed, interKey)
	return root, inter, leaf
}

func keygen(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A TLS 1.2 handshake records the whole chain the server presented, leaf
// first, with hashes computed over the exact DER bytes.
func TestTLS12RecordsFullChain(t *testing.T) {
	root, inter, leaf := chainPKI(t)
	server := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leaf.Certificate[0], inter.Certificate[0], root.Certificate[0]},
			PrivateKey:  leaf.PrivateKey,
		}},
	}
	hs, ok := handshake(t, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}, server, 0)
	if !ok {
		t.Fatal("no handshake reported")
	}
	if len(hs.Chain) != 3 {
		t.Fatalf("chain has %d entries: %+v", len(hs.Chain), hs.Chain)
	}
	parsed := make([]*x509.Certificate, 3)
	for i, der := range [][]byte{leaf.Certificate[0], inter.Certificate[0], root.Certificate[0]} {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		parsed[i] = cert
		got := hs.Chain[i]
		certSum := sha256.Sum256(cert.Raw)
		spkiSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if got.CertSha256 != hex.EncodeToString(certSum[:]) || got.SpkiSha256 != hex.EncodeToString(spkiSum[:]) ||
			got.SpkiSha256Base64 != base64.StdEncoding.EncodeToString(spkiSum[:]) {
			t.Errorf("chain[%d] hashes = %+v", i, got)
		}
		if got.Name != cert.Subject.CommonName || got.Subject != cert.Subject.String() || got.Issuer != cert.Issuer.String() {
			t.Errorf("chain[%d] names = %+v", i, got)
		}
		if got.IsCA != cert.IsCA {
			t.Errorf("chain[%d] IsCA = %v, want %v", i, got.IsCA, cert.IsCA)
		}
		self := bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil
		if got.SelfSigned != self {
			t.Errorf("chain[%d] SelfSigned = %v, want %v", i, got.SelfSigned, self)
		}
		if got.KeyName != "ECDSA-P256" || got.KeyBits != 256 {
			t.Errorf("chain[%d] key = %s/%d", i, got.KeyName, got.KeyBits)
		}
		if got.SerialNumber != cert.SerialNumber.Text(16) || got.SignatureAlgorithm != "ECDSA-SHA256" ||
			got.NotValidBefore != cert.NotBefore.UTC().Format(time.RFC3339) || got.NotValidAfter != cert.NotAfter.UTC().Format(time.RFC3339) {
			t.Errorf("chain[%d] serial/validity/signature = %+v", i, got)
		}
	}
	// Existing fields still describe the first certificate (the leaf).
	if hs.ServerKey != "ECDSA-P-256" || hs.CertSignature != "ECDSA-SHA256" {
		t.Errorf("leaf fields: serverKey %q certSignature %q", hs.ServerKey, hs.CertSignature)
	}
	if hs.Chain[1].Issuer != parsed[2].Subject.String() || hs.Chain[0].Issuer != parsed[1].Subject.String() {
		t.Errorf("chain order or issuer linkage: %+v", hs.Chain)
	}
}

// The chain is bounded: an eleventh presented certificate is dropped.
func TestTLS12ChainStopsAtTenCertificates(t *testing.T) {
	n := 11
	ders := make([][]byte, n)
	keys := make([]*ecdsa.PrivateKey, n)
	for i := range ders {
		keys[i] = keygen(t)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject:      pkix.Name{CommonName: fmt.Sprintf("bound-%02d.observe.test", i)},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &keys[i].PublicKey, keys[i])
		if err != nil {
			t.Fatal(err)
		}
		ders[i] = der
	}
	server := &tls.Config{Certificates: []tls.Certificate{{Certificate: ders, PrivateKey: keys[0]}}}
	hs, ok := handshake(t, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}, server, 0)
	if !ok {
		t.Fatal("no handshake reported")
	}
	if len(hs.Chain) != maxChainCerts {
		t.Fatalf("chain has %d entries, want %d", len(hs.Chain), maxChainCerts)
	}
	for i, cert := range hs.Chain {
		if want := fmt.Sprintf("bound-%02d.observe.test", i); cert.Name != want {
			t.Errorf("chain[%d].Name = %q, want %q", i, cert.Name, want)
		}
	}
}

// The chain stops before its 64 KiB certificate budget is crossed, keeping
// the certificates that fit. Fat certificates (a large unknown extension)
// make four of them overrun the budget.
func TestTLS12ChainStopsAtByteBudget(t *testing.T) {
	var ders [][]byte
	for i := range 4 {
		ders = append(ders, fatCert(t, fmt.Sprintf("fat-%d", i), 20<<10))
	}
	hs := observeCertificates(ders...)
	var total int
	for _, der := range ders {
		total += len(der)
	}
	if total <= maxChainBytes {
		t.Fatalf("test premise: %d bytes of certificates must exceed the %d budget", total, maxChainBytes)
	}
	if len(hs.Chain) != 3 {
		t.Fatalf("chain has %d entries, want the 3 that fit the budget", len(hs.Chain))
	}
	if hs.Chain[0].Name != "fat-0" || hs.Chain[2].Name != "fat-2" || hs.ServerKey != "ECDSA-P-256" {
		t.Fatalf("chain = %+v", hs.Chain)
	}
}

// A leaf larger than the whole chain budget still fills ServerKey and
// CertSignature, as before chains were recorded, but is not a chain record.
func TestTLS12OversizedLeafKeepsServerKey(t *testing.T) {
	hs := observeCertificates(fatCert(t, "fat-leaf", maxChainBytes))
	if hs.ServerKey != "ECDSA-P-256" || hs.CertSignature != "ECDSA-SHA256" {
		t.Errorf("leaf fields: serverKey %q certSignature %q", hs.ServerKey, hs.CertSignature)
	}
	if hs.Chain != nil {
		t.Errorf("chain = %+v, want none past the budget", hs.Chain)
	}
}

// fatCert is a self-signed certificate made at least pad bytes large by an
// unknown extension.
func fatCert(t *testing.T, cn string, pad int) []byte {
	t.Helper()
	key := keygen(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 99},
			Value: make([]byte, pad),
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// observeCertificates feeds a TLS 1.2 ServerHello and a Certificate message
// carrying ders to an observer and returns what it recorded.
func observeCertificates(ders ...[]byte) Handshake {
	var body []byte
	for _, der := range ders {
		body = append(body, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
		body = append(body, der...)
	}
	obs := New(nil)
	_, _ = obs.Server().Write(serverHelloRecord())
	_, _ = obs.Server().Write(handshakeRecords(msgCertificate, append([]byte{byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)))
	obs.Close()
	hs, _ := obs.Result()
	return hs
}

// pqCert loads a certificate generated by testdata/pqc/gen.sh.
func pqCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "pqc", name+".pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s: no PEM block", name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return cert
}

// Post-quantum certificates are named from their OIDs, the same way whatever
// this Go release implements: an ECDSA server certificate under an ML-DSA-44
// intermediate and ML-DSA-65 root (OpenSSL-generated), as a TLS 1.2 server
// would present them.
func TestPostQuantumChainNames(t *testing.T) {
	leaf, inter, root := pqCert(t, "ecdsa-leaf"), pqCert(t, "mldsa44-int"), pqCert(t, "mldsa65-root")
	hs := observeCertificates(leaf.Raw, inter.Raw, root.Raw)
	if len(hs.Chain) != 3 {
		t.Fatalf("chain = %+v", hs.Chain)
	}
	if hs.ServerKey != "ECDSA-P-256" || hs.CertSignature != "ML-DSA-44" {
		t.Errorf("leaf fields: serverKey %q certSignature %q", hs.ServerKey, hs.CertSignature)
	}
	want := []struct {
		key, keyOID, sig, sigOID string
		bits                     int
		selfSigned               bool
	}{
		{"ECDSA-P256", "1.2.840.10045.2.1", "ML-DSA-44", "2.16.840.1.101.3.4.3.17", 256, false},
		{"ML-DSA-44", "2.16.840.1.101.3.4.3.17", "ML-DSA-65", "2.16.840.1.101.3.4.3.18", 0, false},
		{"ML-DSA-65", "2.16.840.1.101.3.4.3.18", "ML-DSA-65", "2.16.840.1.101.3.4.3.18", 0, true},
	}
	for i, w := range want {
		got := hs.Chain[i]
		if got.KeyName != w.key || got.KeyAlgorithmOid != w.keyOID || got.KeyBits != w.bits ||
			got.SignatureAlgorithm != w.sig || got.SignatureAlgorithmOid != w.sigOID || got.SelfSigned != w.selfSigned {
			t.Errorf("chain[%d] = %+v, want %+v", i, got, w)
		}
	}
	// Go 1.27 verifies ML-DSA; an earlier release falls back to self-issued.
	t.Logf("ML-DSA root self-signature unverified: %v", hs.Chain[2].SelfSignedUnverified)
}

// Every post-quantum key and signature is named, including those no Go
// release parses, and a root whose signature cannot be checked is still
// self-signed; a SHA-1 root verifies.
func TestPostQuantumAndLegacyCertificates(t *testing.T) {
	kem := chainCert(pqCert(t, "mlkem768-leaf"))
	if kem.KeyName != "ML-KEM-768" || kem.KeyBits != 0 || kem.KeyAlgorithmOid != "2.16.840.1.101.3.4.4.2" || kem.SignatureAlgorithm != "ML-DSA-44" {
		t.Errorf("ML-KEM leaf = %+v", kem)
	}
	if got := serverKeyString(pqCert(t, "mlkem768-leaf")); got != "ML-KEM-768" {
		t.Errorf("ML-KEM serverKey = %q", got)
	}
	slh := chainCert(pqCert(t, "slhdsa-root"))
	if slh.KeyName != "SLH-DSA-SHA2-128s" || slh.SignatureAlgorithm != "SLH-DSA-SHA2-128s" ||
		slh.SignatureAlgorithmOid != "2.16.840.1.101.3.4.3.20" || !slh.IsCA || !slh.SelfSigned {
		t.Errorf("SLH-DSA root = %+v", slh)
	}
	sha1 := chainCert(pqCert(t, "sha1-root"))
	if sha1.SignatureAlgorithm != "SHA1-RSA" || !sha1.SelfSigned || sha1.SelfSignedUnverified {
		t.Errorf("SHA-1 root = %+v, want a verified self-signature", sha1)
	}
}

// An algorithm with no known name is named by its dotted OID, and a
// self-issued certificate whose signature algorithm is unknown counts as
// self-signed, unverified. The certificate is a generated ECDSA one whose
// key and signature OIDs are rewritten to unassigned arcs of the same length
// (not generated by any real issuer).
func TestUnknownAlgorithmsNamedByOID(t *testing.T) {
	key := keygen(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "unknown-alg"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	// ecdsa-with-SHA256 1.2.840.10045.4.3.2 -> 1.2.840.10045.4.3.99 (both
	// copies), id-ecPublicKey 1.2.840.10045.2.1 -> 1.2.840.10045.2.99.
	der = bytes.ReplaceAll(der, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x63})
	der = bytes.ReplaceAll(der, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01}, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x63})
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	got := chainCert(cert)
	if got.KeyName != "1.2.840.10045.2.99" || got.KeyAlgorithmOid != "1.2.840.10045.2.99" ||
		got.SignatureAlgorithm != "1.2.840.10045.4.3.99" || !got.SelfSigned || !got.SelfSignedUnverified {
		t.Errorf("unknown algorithms = %+v", got)
	}
}

// Malformed certificate lists stop the walk without a panic, keeping what
// already parsed.
func TestMalformedCertificateList(t *testing.T) {
	root, inter, leaf := chainPKI(t)
	good := [][]byte{leaf.Certificate[0], inter.Certificate[0], root.Certificate[0]}

	// listBody frames entries as the certificate_list vector does: each
	// 3-byte length-prefixed.
	listBody := func(entries ...[]byte) []byte {
		var body []byte
		for _, e := range entries {
			body = append(body, byte(len(e)>>16), byte(len(e)>>8), byte(len(e)))
			body = append(body, e...)
		}
		return append([]byte{byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	}
	certRecord := func(body []byte) []byte { return handshakeRecords(msgCertificate, body) }

	cases := map[string]struct {
		record []byte
		keep   int
	}{
		"empty list":           {certRecord([]byte{0, 0, 0}), 0},
		"zero-length entry":    {certRecord(listBody(nil, nil)), 0},
		"garbage DER":          {certRecord(listBody([]byte("not a certificate"))), 0},
		"truncated list":       {certRecord([]byte{0, 1, 0, 0}), 0}, // announces 256 bytes, has none
		"length beyond list":   {certRecord(append([]byte{0, 0, 30}, 0xff, 0xff, 0xff)), 0},
		"garbage after two":    {certRecord(append(listBody(good[0], good[1]), 0, 0, 1, 'x')), 2},
		"truncated last entry": {certRecord(append(listBody(good[0]), 0, 0, 20, 1, 2)), 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			obs := New(nil)
			_, _ = obs.Server().Write(serverHelloRecord())
			_, _ = obs.Server().Write(tc.record)
			obs.Close()
			hs, _ := obs.Result()
			if len(hs.Chain) != tc.keep {
				t.Fatalf("chain = %+v, want %d entries kept", hs.Chain, tc.keep)
			}
		})
	}
}

// serverHelloRecord is a final TLS 1.2 ServerHello with no extensions.
func serverHelloRecord() []byte {
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)          // session id
	body = append(body, 0x00, 0x2f) // TLS_RSA_WITH_AES_128_CBC_SHA
	body = append(body, 0)          // compression
	body = append(body, 0, 0)       // extensions
	return handshakeRecords(msgServerHello, body)
}

// handshakeRecords frames one handshake message, split into records of at
// most 2^14 bytes as a real sender would.
func handshakeRecords(typ byte, body []byte) []byte {
	msg := []byte{typ, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	msg = append(msg, body...)
	var out []byte
	for len(msg) > 0 {
		n := min(len(msg), 1<<14)
		out = append(out, 22, 3, 3, byte(n>>8), byte(n))
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

func TestTLS12Resumption(t *testing.T) {
	certs(t)
	cache := tls.NewLRUClientSessionCache(4)
	client := &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, ClientSessionCache: cache, ServerName: "observe.test"}
	server := &tls.Config{Certificates: []tls.Certificate{ecCert}}
	if first, ok := handshake(t, client, server, 0); !ok || first.Resumed || first.ServerKey != "ECDSA-P-256" {
		t.Fatalf("first handshake = %+v", first)
	}
	second, ok := handshake(t, client, server, 0)
	if !ok || !second.Resumed || second.ServerKey != "" || second.Version != 0x0303 || second.Chain != nil {
		t.Fatalf("resumed handshake = %+v", second)
	}
}

func TestNonTLSIsIgnored(t *testing.T) {
	called := false
	obs := New(func(Handshake) { called = true })
	_, _ = obs.Client().Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	_, _ = obs.Server().Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	obs.Close()
	if _, ok := obs.Result(); ok || called {
		t.Fatal("a non-TLS stream was reported")
	}
}

func TestOversizedInputStops(t *testing.T) {
	obs := New(nil)
	// A handshake record header announcing a message far past the budget.
	_, _ = obs.Server().Write([]byte{22, 3, 3, 0x40, 0x00, 2, 0xff, 0xff, 0xff})
	big := make([]byte, 1<<20)
	_, _ = obs.Server().Write(big)
	if !obs.server.done || obs.server.records != nil {
		t.Fatal("observer kept buffering past its limit")
	}
}

// clientHello builds a minimal ClientHello record with the given extensions.
func clientHello(exts ...[]byte) []byte {
	var ext []byte
	for _, e := range exts {
		ext = append(ext, e...)
	}
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                // session id
	body = append(body, 0, 2, 0x13, 0x01) // one suite
	body = append(body, 1, 0)             // null compression
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	msg := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 1, byte(len(msg) >> 8), byte(len(msg))}, msg...)
}

func extension(typ uint16, data []byte) []byte {
	e := binary.BigEndian.AppendUint16(nil, typ)
	e = binary.BigEndian.AppendUint16(e, uint16(len(data)))
	return append(e, data...)
}

func TestClientHelloSNIAndECH(t *testing.T) {
	name := []byte("outer.example")
	sni := binary.BigEndian.AppendUint16(nil, uint16(len(name)+3))
	sni = append(sni, 0)
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(name)))
	sni = append(sni, name...)
	obs := New(nil)
	_, _ = obs.Client().Write(clientHello(extension(extServerName, sni), extension(extECH, []byte{0})))
	if obs.hs.ServerName != "outer.example" || !obs.hs.ECH {
		t.Fatalf("client hello = %+v", obs.hs)
	}
}

func TestSuiteDecomposition(t *testing.T) {
	cases := map[uint16]SuiteInfo{
		0xC030: {Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Known: true, KeyExchange: "ECDHE", Authentication: "RSA", Encryption: "AES", EncryptionBits: 256, Mode: "GCM", Hash: "SHA384"},
		0x1301: {Name: "TLS_AES_128_GCM_SHA256", Known: true, Encryption: "AES", EncryptionBits: 128, Mode: "GCM", Hash: "SHA256"},
		0x1305: {Name: "TLS_AES_128_CCM_8_SHA256", Known: true, Encryption: "AES", EncryptionBits: 128, Mode: "CCM8", Hash: "SHA256"},
		0x000A: {Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Known: true, KeyExchange: "RSA", Authentication: "RSA", Encryption: "3DES", EncryptionBits: 112, Mode: "CBC", Hash: "SHA1"},
		0xCCA8: {Name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", Known: true, KeyExchange: "ECDHE", Authentication: "RSA", Encryption: "CHACHA20", EncryptionBits: 256, Mode: "POLY1305", Hash: "SHA256"},
		0x009F: {Name: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", Known: true, KeyExchange: "DHE", Authentication: "RSA", Encryption: "AES", EncryptionBits: 256, Mode: "GCM", Hash: "SHA384"},
		0xFFFF: {Name: "0xFFFF"},
	}
	for id, want := range cases {
		if got := Suite(id); got != want {
			t.Errorf("Suite(%#04x) = %+v, want %+v", id, got, want)
		}
	}
	if VersionName(0x0304) != "TLSv1.3" || VersionName(0x0303) != "TLSv1.2" || GroupName(0x0017) != "secp256r1" || GroupKeyExchange(0x0100) != "DHE" {
		t.Error("version or group naming")
	}
}

// HelloReader reports the ClientHello's SNI once, even when the record
// arrives split across reads, and forwards every byte unchanged.
func TestHelloReaderReportsSNI(t *testing.T) {
	name := []byte("front.example")
	sni := binary.BigEndian.AppendUint16(nil, uint16(len(name)+3))
	sni = append(sni, 0)
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(name)))
	sni = append(sni, name...)
	record := clientHello(extension(extServerName, sni))
	payload := append(append([]byte{}, record...), []byte{23, 3, 3, 0, 2, 0xaa, 0xbb}...)

	var calls int
	var got string
	r := HelloReader(iotestOneByte(bytes.NewReader(payload)), func(name string, ech bool) {
		calls++
		got = name
	})
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatal("HelloReader altered the stream")
	}
	if calls != 1 || got != "front.example" {
		t.Fatalf("onHello calls=%d name=%q", calls, got)
	}
}

func TestHelloReaderIgnoresNonTLS(t *testing.T) {
	called := false
	r := HelloReader(strings.NewReader("GET / HTTP/1.1\r\n\r\n"), func(string, bool) { called = true })
	if _, err := io.ReadAll(r); err != nil || called {
		t.Fatalf("non-TLS stream reported (err=%v)", err)
	}
}

// iotestOneByte returns a reader that yields one byte per Read call.
func iotestOneByte(r io.Reader) io.Reader { return oneByte{r} }

type oneByte struct{ r io.Reader }

func (o oneByte) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}
