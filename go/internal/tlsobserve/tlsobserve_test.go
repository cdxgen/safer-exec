package tlsobserve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
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
	if hs.ServerKey != "" || hs.CertSignature != "" {
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
		want := Handshake{Version: 0x0303, CipherSuite: 0xC02F, Group: 0x0017, ServerKey: "RSA-2048", CertSignature: "SHA256-RSA"}
		if hs != want {
			t.Fatalf("chunk %d: handshake = %+v, want %+v", chunk, hs, want)
		}
	}
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
	if !ok || !second.Resumed || second.ServerKey != "" || second.Version != 0x0303 {
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
