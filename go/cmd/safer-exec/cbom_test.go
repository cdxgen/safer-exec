package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// cbomFixture covers every source the CBOM is built from: TLS 1.3 and 1.2
// suites from the egress proxy (hybrid and classical groups, RSA, ECDSA and
// Ed25519 server keys, finite-field groups), a suite the Linux tracer
// attributed to a library, and traced operations. The two TLS 1.2 proxy
// suites carry the certificate chains their servers presented (cbomChains:
// two roots and one intermediate key certified by both, so the chains share a
// cross-signed SPKI).
func cbomFixture(t *testing.T) *config.CryptoResult {
	chainA, chainB := cbomChains(t)
	return &config.CryptoResult{
		Platform: "linux",
		Libraries: []config.CryptoLibrary{
			{Name: "OpenSSL", Version: "3.0.13", Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3", Source: "proc_maps"},
			{Name: "OpenSSL", Version: "3.0.13", Path: "/opt/app/lib/libssl.so.3", Source: "proc_maps"},
			{Name: "Windows Schannel", Path: `C:\Windows\System32\schannel.dll`, Source: "etw_image_load"},
		},
		Ciphers: []config.CipherInfo{
			{Name: "TLS_AES_128_GCM_SHA256", IANAName: "TLS_AES_128_GCM_SHA256", IANAID: 0x1301, Protocol: "TLSv1.3", Encryption: "AES", EncryptionBits: 128, Mode: "GCM", Hash: "SHA256",
				KeyExchange: "ECDHE+ML-KEM", Group: "X25519MLKEM768", PostQuantum: true, Source: "proxy"},
			{Name: "TLS_AES_256_GCM_SHA384", IANAName: "TLS_AES_256_GCM_SHA384", IANAID: 0x1302, Protocol: "TLSv1.3", Encryption: "AES", EncryptionBits: 256, Mode: "GCM", Hash: "SHA384",
				Group: "SecP384r1MLKEM1024", PostQuantum: true, Source: "proxy"},
			{Name: "TLS_CHACHA20_POLY1305_SHA256", IANAName: "TLS_CHACHA20_POLY1305_SHA256", IANAID: 0x1303, Protocol: "TLSv1.3", Encryption: "CHACHA20", EncryptionBits: 256, Mode: "POLY1305", Hash: "SHA256",
				Group: "x25519", Source: "proxy"},
			{Name: "TLS_AES_128_GCM_SHA256", IANAName: "TLS_AES_128_GCM_SHA256", IANAID: 0x1301, Protocol: "TLSv1.3", Encryption: "AES", EncryptionBits: 128, Mode: "GCM", Hash: "SHA256",
				Group: "X25519Kyber768Draft00", PostQuantum: true, Source: "proxy"},
			{Name: "ECDHE-RSA-AES128-GCM-SHA256", IANAName: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", IANAID: 0xC02F, Protocol: "TLSv1.2", KeyExchange: "ECDHE", Authentication: "RSA",
				Encryption: "AES", EncryptionBits: 128, Mode: "GCM", Hash: "SHA256", Group: "secp256r1", ServerKey: "RSA-2048", Source: "proxy",
				Host: "a.cbom.test:443", Chain: chainA},
			{Name: "ECDHE-ECDSA-AES256-CCM", IANAName: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", IANAID: 0xC0AD, Protocol: "TLSv1.2", KeyExchange: "ECDHE", Authentication: "ECDSA",
				Encryption: "AES", EncryptionBits: 256, Mode: "CCM", Group: "brainpoolP256r1tls13", ServerKey: "ECDSA-P-256", Source: "proxy",
				Host: "b.cbom.test:443", Chain: chainB},
			{Name: "DHE-RSA-AES256-CBC-SHA", IANAName: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", IANAID: 0x0039, Protocol: "TLSv1.2", KeyExchange: "DHE", Authentication: "RSA",
				Encryption: "AES", EncryptionBits: 256, Mode: "CBC", Hash: "SHA1", Group: "DH-2048", ServerKey: "Ed25519", Source: "proxy"},
			{Name: "DES-CBC3-SHA", IANAName: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", IANAID: 0x000A, Protocol: "TLSv1.2", KeyExchange: "RSA", Authentication: "RSA",
				Encryption: "3DES", EncryptionBits: 112, Mode: "CBC", Hash: "SHA", Group: "ffdhe2048", Source: "proxy"},
			{Name: "ECDHE-RSA-AES256-GCM-SHA384", IANAName: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", IANAID: 0xC030, Protocol: "TLSv1.2", Encryption: "AES", EncryptionBits: 256,
				Mode: "GCM", Hash: "SHA384", Library: "OpenSSL", LibraryVersion: "3.0.13", Source: "ebpf_uprobe"},
			{Name: "ECDHE-RSA-CHACHA20-POLY1305", Protocol: "TLSv1.2", Encryption: "CHACHA20", Mode: "POLY1305", Library: "GnuTLS", LibraryVersion: "3.8.3", Source: "ebpf_uprobe"},
		},
		Operations: []config.CryptoOperation{
			{Type: "digest", Algorithm: "SHA-256", Count: 4},
			{Type: "digest", Algorithm: "MD5", Count: 1},
			{Type: "encrypt", Algorithm: "AES", Count: 2},
			{Type: "decrypt", Algorithm: "AES", Count: 2},
		},
	}
}

// cbomChains generates a small PKI: rootA and rootB, one intermediate key
// certified by both (intA, intB — a cross-signed twin pair sharing one SPKI),
// and a leaf issued under intA whose name needs bom-ref escaping. Every hash
// in the returned entries is computed from the generated certificates.
func cbomChains(t *testing.T) (chainA, chainB []config.CertChainEntry) {
	t.Helper()
	rootAKey, rootBKey, intKey, leafKey := testKey(t), testKey(t), testKey(t), testKey(t)
	rootA := testCert(t, "cbom-test-root-a", true, rootAKey, nil, nil)
	rootB := testCert(t, "cbom-test-root-b", true, rootBKey, nil, nil)
	intA := testCert(t, "cbom-test-intermediate", true, intKey, rootA, rootAKey)
	intB := testCert(t, "cbom-test-intermediate", true, intKey, rootB, rootBKey)
	leaf := testCert(t, "cbom-test-leaf (Let's: a@b+c)", false, leafKey, intA, intKey)
	return chainEntries(leaf, intA, rootA), chainEntries(intB, rootB)
}

// chainEntries maps generated certificates to the observed-chain form. It
// mirrors what tlsobserve records, computing every hash from the DER.
func chainEntries(certs ...*x509.Certificate) []config.CertChainEntry {
	out := make([]config.CertChainEntry, 0, len(certs))
	for _, cert := range certs {
		certSum := sha256.Sum256(cert.Raw)
		spkiSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		bits := cert.PublicKey.(*ecdsa.PublicKey).Curve.Params().BitSize
		out = append(out, config.CertChainEntry{
			Name:               cert.Subject.CommonName,
			Subject:            cert.Subject.String(),
			Issuer:             cert.Issuer.String(),
			SerialNumber:       cert.SerialNumber.Text(16),
			NotValidBefore:     cert.NotBefore.UTC().Format(time.RFC3339),
			NotValidAfter:      cert.NotAfter.UTC().Format(time.RFC3339),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			CertSha256:         hex.EncodeToString(certSum[:]),
			SpkiSha256:         hex.EncodeToString(spkiSum[:]),
			SpkiSha256Base64:   base64.StdEncoding.EncodeToString(spkiSum[:]),
			KeyName:            fmt.Sprintf("ECDSA-P%d", bits),
			KeyBits:            bits,
			IsCA:               cert.IsCA,
			SelfSigned:         bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil,
		})
	}
	return out
}

// fixtureChains returns the chains cbomFixture's TLS 1.2 suites carry, in
// order, with the host each was presented by.
func fixtureChains(r *config.CryptoResult) (chains [][]config.CertChainEntry, hosts []string) {
	for _, c := range r.Ciphers {
		if c.Chain != nil {
			chains = append(chains, c.Chain)
			hosts = append(hosts, c.Host)
		}
	}
	return chains, hosts
}

func cbomJSON(t *testing.T, r *config.CryptoResult) any {
	t.Helper()
	data, err := json.Marshal(buildCBOM(r))
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestCBOMValidatesAgainstCycloneDX(t *testing.T) {
	schemas := loadCycloneDXSchemas(t)
	for _, r := range []*config.CryptoResult{cbomFixture(t), {Platform: "darwin"}} {
		doc := cbomJSON(t, r)
		for _, schema := range []string{"bom-1.6.schema.json", "bom-1.7.schema.json"} {
			if errs := schemas.validate(schema, doc); len(errs) > 0 {
				t.Errorf("CBOM is not valid against %s:\n  %s", schema, strings.Join(errs, "\n  "))
			}
		}
	}
}

func TestCBOMContents(t *testing.T) {
	doc := buildCBOM(cbomFixture(t))
	byRef := map[string]cbomComponent{}
	byName := map[string]cbomComponent{}
	for _, c := range doc.Components {
		if c.BomRef == "" {
			t.Errorf("component %s has no bom-ref", c.Name)
		}
		if _, dup := byRef[c.BomRef]; dup {
			t.Errorf("bom-ref %s is not unique", c.BomRef)
		}
		byRef[c.BomRef] = c
		byName[c.Name] = c
	}

	// Algorithms with a standard OID carry it, in their bom-ref too.
	for name, oid := range map[string]string{
		"AES-128-GCM": "2.16.840.1.101.3.4.1.6", "AES-256-GCM": "2.16.840.1.101.3.4.1.46", "AES-256-CCM": "2.16.840.1.101.3.4.1.47",
		"AES-256-CBC": "2.16.840.1.101.3.4.1.42", "ChaCha20-Poly1305": "1.2.840.113549.1.9.16.3.18", "3DES-CBC": "1.2.840.113549.3.7",
		"SHA-1": "1.3.14.3.2.26", "SHA-256": "2.16.840.1.101.3.4.2.1", "SHA-384": "2.16.840.1.101.3.4.2.2", "MD5": "1.2.840.113549.2.5",
		"x25519": "1.3.101.110", "secp256r1": "1.2.840.10045.3.1.7", "secp384r1": "1.3.132.0.34", "brainpoolP256r1": "1.3.36.3.3.2.8.1.1.7",
		"ML-KEM-768": "2.16.840.1.101.3.4.4.2", "ML-KEM-1024": "2.16.840.1.101.3.4.4.3",
		"RSA-2048": "1.2.840.113549.1.1.1", "ECDSA-P-256": "1.2.840.10045.2.1", "Ed25519": "1.3.101.112",
	} {
		c, ok := byName[name]
		if !ok || c.CryptoProperties == nil {
			t.Errorf("CBOM lacks algorithm %s", name)
			continue
		}
		if c.CryptoProperties.OID != oid || c.BomRef != "crypto/algorithm/"+name+"@"+oid {
			t.Errorf("%s: oid %q, bom-ref %q", name, c.CryptoProperties.OID, c.BomRef)
		}
	}
	// Finite-field groups are Diffie-Hellman; a traced AES operation knows no
	// key size or mode. The Kyber draft adds nothing beyond its curve, and
	// hybrids are not components of their own.
	for name, oid := range map[string]string{"ffdhe2048": "1.2.840.113549.1.3.1", "DH-2048": "1.2.840.113549.1.3.1", "AES": "2.16.840.1.101.3.4.1"} {
		if c, ok := byName[name]; !ok || c.CryptoProperties.OID != oid {
			t.Errorf("%s: %+v", name, c)
		}
	}
	for _, name := range []string{"X25519MLKEM768", "SecP384r1MLKEM1024", "X25519Kyber768Draft00", "TLS_AES_128_GCM_SHA256"} {
		if _, ok := byName[name]; ok {
			t.Errorf("%s should not be a component", name)
		}
	}
	if p := byName["ML-KEM-768"].CryptoProperties.AlgorithmProperties; p.Primitive != "kem" || p.NistQuantumSecurityLevel != 3 {
		t.Errorf("ML-KEM-768 = %+v", p)
	}
	if p := byName["AES-128-GCM"].CryptoProperties.AlgorithmProperties; p.Primitive != "ae" || p.Mode != "gcm" || p.ParameterSetIdentifier != "128" {
		t.Errorf("AES-128-GCM = %+v", p)
	}
	if p := byName["AES"].CryptoProperties.AlgorithmProperties; !slices.Equal(p.CryptoFunctions, []string{"encrypt", "decrypt"}) {
		t.Errorf("traced AES operations = %+v", p)
	}

	// Libraries are library components, one per name and version, with the
	// paths they were loaded from.
	ssl := byRef["crypto/library/OpenSSL@3.0.13"]
	if ssl.Type != "library" || ssl.Evidence == nil || len(ssl.Evidence.Occurrences) != 2 {
		t.Errorf("OpenSSL = %+v", ssl)
	}
	if c := byRef["crypto/library/Windows%20Schannel"]; c.Type != "library" || c.Version != "" {
		t.Errorf("Schannel = %+v", c)
	}

	// Suites refer to algorithms by bom-ref.
	tls13 := byRef["crypto/protocol/tls@1.3"]
	if tls13.Name != "TLSv1.3" || tls13.CryptoProperties.ProtocolProperties == nil {
		t.Fatalf("TLS 1.3 = %+v", tls13)
	}
	suites := tls13.CryptoProperties.ProtocolProperties.CipherSuites
	if len(suites) != 3 || suites[0].Name != "TLS_AES_128_GCM_SHA256" || !slices.Equal(suites[0].Identifiers, []string{"0x13", "0x01"}) {
		t.Errorf("TLS 1.3 suites = %+v", suites)
	}
	want := []string{
		"crypto/algorithm/AES-128-GCM@2.16.840.1.101.3.4.1.6", "crypto/algorithm/SHA-256@2.16.840.1.101.3.4.2.1",
		"crypto/algorithm/x25519@1.3.101.110", "crypto/algorithm/ML-KEM-768@2.16.840.1.101.3.4.4.2",
	}
	if !slices.Equal(suites[0].Algorithms, want) {
		t.Errorf("TLS_AES_128_GCM_SHA256 algorithms = %v, want %v", suites[0].Algorithms, want)
	}
	for _, p := range []cbomComponent{tls13, byRef["crypto/protocol/tls@1.2"]} {
		for _, s := range p.CryptoProperties.ProtocolProperties.CipherSuites {
			for _, ref := range s.Algorithms {
				if _, ok := byRef[ref]; !ok {
					t.Errorf("suite %s refers to missing %s", s.Name, ref)
				}
			}
		}
	}

	// A library the tracer saw negotiate a suite provides its algorithms.
	provides := map[string][]string{}
	for _, d := range doc.Dependencies {
		provides[d.Ref] = d.Provides
		for _, ref := range append([]string{d.Ref}, d.Provides...) {
			if _, ok := byRef[ref]; !ok {
				t.Errorf("dependency refers to missing %s", ref)
			}
		}
	}
	if got := provides["crypto/library/OpenSSL@3.0.13"]; !slices.Contains(got, "crypto/algorithm/AES-256-GCM@2.16.840.1.101.3.4.1.46") || !slices.Contains(got, "crypto/protocol/tls@1.2") {
		t.Errorf("OpenSSL provides %v", got)
	}
	if got := provides["crypto/library/GnuTLS@3.8.3"]; !slices.Contains(got, "crypto/algorithm/ChaCha20-Poly1305@1.2.840.113549.1.9.16.3.18") {
		t.Errorf("GnuTLS provides %v", got)
	}
	if doc.Metadata == nil || doc.Metadata.Tools.Components[0].Version != version {
		t.Errorf("metadata = %+v", doc.Metadata)
	}
}

// propValue returns a component's cdx:crypto property.
func propValue(c cbomComponent, name string) (string, bool) {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

// The presented chains become certificate and public-key components: one per
// certificate, one per distinct SPKI (the cross-signed twins share a key), in
// the bom-ref formats cdxgen uses, linked from the TLS protocol component and
// from each certificate to its key, with the presenting servers as
// occurrences.
func TestCBOMCertificateAndPublicKeyComponents(t *testing.T) {
	r := cbomFixture(t)
	chains, hosts := fixtureChains(r)
	chainA, chainB := chains[0], chains[1]
	doc := buildCBOM(r)
	byRef := map[string]cbomComponent{}
	for _, c := range doc.Components {
		byRef[c.BomRef] = c
	}
	certRef := func(e config.CertChainEntry) string {
		return "crypto/certificate/" + encodeURIComponent(e.Name) + "@sha256:" + e.CertSha256
	}
	keyRef := func(e config.CertChainEntry) string {
		return "crypto/public-key/" + encodeURIComponent(e.KeyName) + "@spki-sha256:" + e.SpkiSha256
	}
	locations := func(c cbomComponent) []string {
		var out []string
		if c.Evidence != nil {
			for _, o := range c.Evidence.Occurrences {
				out = append(out, o.Location)
			}
		}
		return out
	}

	// The leaf's name carries characters url.PathEscape and JavaScript's
	// encodeURIComponent treat differently; the ref must be cdxgen's.
	if want := "crypto/certificate/cbom-test-leaf%20(Let's%3A%20a%40b%2Bc)@sha256:" + chainA[0].CertSha256; certRef(chainA[0]) != want {
		t.Fatalf("leaf bom-ref = %s, want %s", certRef(chainA[0]), want)
	}
	wantRoles := []string{"leaf", "intermediate", "root"}
	for i, e := range chainA {
		c, ok := byRef[certRef(e)]
		if !ok {
			t.Fatalf("chainA[%d]: no certificate component %s", i, certRef(e))
		}
		if c.Type != "cryptographic-asset" || c.Version != e.CertSha256 || c.Name != e.Name {
			t.Errorf("chainA[%d] component = %+v", i, c)
		}
		cp := c.CryptoProperties
		if cp == nil || cp.AssetType != "certificate" || cp.CertificateProperties == nil {
			t.Fatalf("chainA[%d] cryptoProperties = %+v", i, cp)
		}
		want := cbomCertProps{
			SubjectName:         e.Subject,
			IssuerName:          e.Issuer,
			NotValidBefore:      e.NotValidBefore,
			NotValidAfter:       e.NotValidAfter,
			SubjectPublicKeyRef: keyRef(e),
			CertificateFormat:   "X.509",
		}
		if *cp.CertificateProperties != want {
			t.Errorf("chainA[%d] certificateProperties = %+v, want %+v", i, *cp.CertificateProperties, want)
		}
		for name, want := range map[string]string{
			"cdx:crypto:spkiSha256":         e.SpkiSha256,
			"cdx:crypto:fingerprint":        e.CertSha256,
			"cdx:crypto:certRole":           wantRoles[i],
			"cdx:crypto:selfSigned":         strconv.FormatBool(e.SelfSigned),
			"cdx:crypto:isCA":               strconv.FormatBool(e.IsCA),
			"cdx:crypto:signatureAlgorithm": "ECDSA-SHA256",
			"cdx:crypto:sourceType":         "observed-tls",
		} {
			if got, ok := propValue(c, name); !ok || got != want {
				t.Errorf("chainA[%d] %s = %q, want %q", i, name, got, want)
			}
		}
		if got := locations(c); !slices.Equal(got, []string{"tls://" + hosts[0]}) {
			t.Errorf("chainA[%d] occurrences = %v", i, got)
		}
	}
	if role, _ := propValue(byRef[certRef(chainB[0])], "cdx:crypto:certRole"); role != "intermediate" {
		t.Errorf("cross-signed twin role = %q, want intermediate", role)
	}

	// One public-key component per distinct SPKI: leaf, shared intermediate
	// key, rootA, rootB. The shared key was presented by both servers.
	keyRefs := map[string]bool{}
	for _, e := range append(slices.Clone(chainA), chainB...) {
		ref := keyRef(e)
		c, ok := byRef[ref]
		if !ok {
			t.Fatalf("no public-key component %s", ref)
		}
		keyRefs[ref] = true
		rcm := c.CryptoProperties.RelatedCryptoMaterialProps
		if c.CryptoProperties.AssetType != "related-crypto-material" || rcm == nil || rcm.Type != "public-key" || rcm.Format != "SPKI" || rcm.Size != 256 {
			t.Errorf("public key %s = %+v", ref, c.CryptoProperties)
		}
		if got, ok := propValue(c, "cdx:crypto:spkiSha256Base64"); !ok || got != e.SpkiSha256Base64 {
			t.Errorf("public key %s pin property = %q", ref, got)
		}
		if got, _ := propValue(c, "cdx:crypto:sourceType"); got != "certificate" {
			t.Errorf("public key %s sourceType = %q", ref, got)
		}
	}
	if len(keyRefs) != 4 {
		t.Errorf("%d public-key components, want 4 (the twins must share one): %v", len(keyRefs), keyRefs)
	}
	if got := locations(byRef[keyRef(chainB[0])]); !slices.Equal(got, []string{"tls://" + hosts[0], "tls://" + hosts[1]}) {
		t.Errorf("shared intermediate key occurrences = %v", got)
	}

	// The TLS 1.2 protocol component provides every chain asset, and each
	// certificate provides its public key.
	provides := map[string][]string{}
	for _, d := range doc.Dependencies {
		provides[d.Ref] = d.Provides
	}
	tls12 := provides["crypto/protocol/tls@1.2"]
	for _, e := range append(slices.Clone(chainA), chainB...) {
		if !slices.Contains(tls12, certRef(e)) || !slices.Contains(tls12, keyRef(e)) {
			t.Errorf("TLS 1.2 does not provide %s and its key", certRef(e))
		}
		if got := provides[certRef(e)]; !slices.Equal(got, []string{keyRef(e)}) {
			t.Errorf("certificate %s provides %v, want [%s]", certRef(e), got, keyRef(e))
		}
	}
}

// encodeURIComponent must agree with JavaScript's byte for byte (expected
// values from Node.js), or cdxgen and safer-exec name one certificate twice.
func TestEncodeURIComponent(t *testing.T) {
	for in, want := range map[string]string{
		"R3":                    "R3",
		"-_.!~*'()":             "-_.!~*'()",
		"a/b;c,d?e=f&g$h#i%j":   "a%2Fb%3Bc%2Cd%3Fe%3Df%26g%24h%23i%25j",
		"Arany (Class Gold) Fő": "Arany%20(Class%20Gold)%20F%C5%91",
		"RSA-2048":              "RSA-2048",
	} {
		if got := encodeURIComponent(in); got != want {
			t.Errorf("encodeURIComponent(%q) = %q, want %q", in, got, want)
		}
	}
}

// Building the CBOM twice from the same observations yields identical bytes
// once the metadata timestamp is set aside: no map-iteration order reaches
// the output.
func TestCBOMDeterministic(t *testing.T) {
	r := cbomFixture(t)
	docs := make([][]byte, 2)
	for i := range docs {
		doc := buildCBOM(r)
		doc.Metadata.Timestamp = ""
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		docs[i] = data
	}
	if !bytes.Equal(docs[0], docs[1]) {
		t.Fatal("two builds of the same result differ")
	}
}

// The validator must catch what the CBOM of safer-exec 1.1.1 got wrong, or a
// pass above would mean nothing.
func TestCycloneDXValidatorRejectsInvalidCBOM(t *testing.T) {
	schemas := loadCycloneDXSchemas(t)
	var doc any
	if err := json.Unmarshal([]byte(`{
		"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
		"metadata": {"timestamp": "yesterday"},
		"components": [
			{"type": "cryptographic-asset", "name": "OpenSSL", "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {"type": "library"}}},
			{"type": "cryptographic-asset", "name": "TLS_AES_128_GCM_SHA256", "cryptoProperties": {"assetType": "algorithm",
				"algorithmProperties": {"primitive": "aead", "mode": "GCM", "executionEnvironment": "OpenSSL", "cryptoFunctions": ["keyagree"]}}},
			{"type": "cryptographic-asset", "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "tls", "cipherSuites": [{"name": "x", "algorithms": [""]}]}}}
		]
	}`), &doc); err != nil {
		t.Fatal(err)
	}
	for _, schema := range []string{"bom-1.6.schema.json", "bom-1.7.schema.json"} {
		errs := strings.Join(schemas.validate(schema, doc), "\n")
		for _, at := range []string{
			"$.metadata.timestamp", "$.components[0].cryptoProperties.relatedCryptoMaterialProperties.type",
			"$.components[1].cryptoProperties.algorithmProperties.primitive", "$.components[1].cryptoProperties.algorithmProperties.mode",
			"$.components[1].cryptoProperties.algorithmProperties.executionEnvironment",
			"$.components[1].cryptoProperties.algorithmProperties.cryptoFunctions[0]", "$.components[2]: missing name",
			"$.components[2].cryptoProperties.protocolProperties.cipherSuites[0].algorithms[0]",
		} {
			if !strings.Contains(errs, at) {
				t.Errorf("%s: no error at %s in:\n%s", schema, at, errs)
			}
		}
	}
}

// cycloneDXSchemas is a JSON Schema draft-07 validator for the keywords the
// vendored CycloneDX schemas use. It fails on any keyword it does not know, so
// a schema update cannot pass by being half-understood.
type cycloneDXSchemas map[string]any

func loadCycloneDXSchemas(t *testing.T) cycloneDXSchemas {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "cyclonedx", "*.schema.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no schemas: %v", err)
	}
	s := cycloneDXSchemas{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		s[filepath.Base(f)] = doc
	}
	return s
}

func (s cycloneDXSchemas) validate(file string, instance any) []string {
	var errs []string
	s.check(file, s[file], instance, "$", &errs)
	return errs
}

// resolve follows a $ref: a JSON pointer, optionally into another schema
// named relative to the CycloneDX schema $id.
func (s cycloneDXSchemas) resolve(file, ref string) (string, any) {
	target, pointer, _ := strings.Cut(ref, "#")
	if target != "" {
		file = path.Base(target)
	}
	node := s[file]
	for _, tok := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		if tok == "" {
			continue
		}
		m, _ := node.(map[string]any)
		node = m[strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")]
	}
	return file, node
}

func (s cycloneDXSchemas) check(file string, schema, v any, at string, errs *[]string) {
	fail := func(format string, args ...any) {
		*errs = append(*errs, at+": "+fmt.Sprintf(format, args...))
	}
	passes := func(sub any) bool {
		var e []string
		s.check(file, sub, v, at, &e)
		return len(e) == 0
	}
	sc, ok := schema.(map[string]any)
	if !ok {
		if b, isBool := schema.(bool); !isBool {
			fail("unresolved schema %v", schema)
		} else if !b {
			fail("not allowed")
		}
		return
	}
	obj, isObj := v.(map[string]any)
	arr, isArr := v.([]any)
	str, isStr := v.(string)
	num, isNum := v.(float64)
	for kw, arg := range sc {
		switch kw {
		case "title", "description", "examples", "default", "$comment", "$schema", "$id", "definitions", "deprecated", "meta:enum", "then", "else":
		case "$ref":
			f, target := s.resolve(file, arg.(string))
			s.check(f, target, v, at, errs)
		case "type":
			types, _ := arg.([]any)
			if t, single := arg.(string); single {
				types = []any{t}
			}
			if !slices.ContainsFunc(types, func(t any) bool { return jsonType(v, t.(string)) }) {
				fail("is not of type %v", arg)
			}
		case "enum":
			if !slices.ContainsFunc(arg.([]any), func(e any) bool { return reflect.DeepEqual(e, v) }) {
				fail("%v is not one of %v", v, arg)
			}
		case "const":
			if !reflect.DeepEqual(arg, v) {
				fail("%v is not %v", v, arg)
			}
		case "properties":
			for k, sub := range arg.(map[string]any) {
				if val, ok := obj[k]; isObj && ok {
					s.check(file, sub, val, at+"."+k, errs)
				}
			}
		case "additionalProperties":
			props, _ := sc["properties"].(map[string]any)
			for k, val := range obj {
				if _, known := props[k]; !known {
					if arg == false {
						fail("%s is not allowed", k)
					} else {
						s.check(file, arg, val, at+"."+k, errs)
					}
				}
			}
		case "required":
			for _, k := range arg.([]any) {
				if _, ok := obj[k.(string)]; isObj && !ok {
					fail("missing %s", k)
				}
			}
		case "items":
			if tuple, isTuple := arg.([]any); isTuple {
				for i := 0; isArr && i < len(arr) && i < len(tuple); i++ {
					s.check(file, tuple[i], arr[i], fmt.Sprintf("%s[%d]", at, i), errs)
				}
			} else {
				for i, item := range arr {
					s.check(file, arg, item, fmt.Sprintf("%s[%d]", at, i), errs)
				}
			}
		case "additionalItems":
			if tuple, isTuple := sc["items"].([]any); isTuple {
				for i := len(tuple); isArr && i < len(arr); i++ {
					s.check(file, arg, arr[i], fmt.Sprintf("%s[%d]", at, i), errs)
				}
			}
		case "minItems", "maxItems":
			if n := int(arg.(float64)); isArr && (kw == "minItems" && len(arr) < n || kw == "maxItems" && len(arr) > n) {
				fail("has %d items (%s %d)", len(arr), kw, n)
			}
		case "uniqueItems":
			for i := range arr {
				for j := i + 1; arg == true && j < len(arr); j++ {
					if reflect.DeepEqual(arr[i], arr[j]) {
						fail("items %d and %d are equal", i, j)
					}
				}
			}
		case "minLength", "maxLength":
			if n := int(arg.(float64)); isStr && (kw == "minLength" && utf8.RuneCountInString(str) < n || kw == "maxLength" && utf8.RuneCountInString(str) > n) {
				fail("length %d (%s %d)", utf8.RuneCountInString(str), kw, n)
			}
		case "pattern":
			if isStr && !regexp.MustCompile(arg.(string)).MatchString(str) {
				fail("%q does not match %s", str, arg)
			}
		case "minimum", "maximum":
			if n := arg.(float64); isNum && (kw == "minimum" && num < n || kw == "maximum" && num > n) {
				fail("%v (%s %v)", num, kw, n)
			}
		case "format":
			if _, err := time.Parse(time.RFC3339, str); arg == "date-time" && isStr && err != nil {
				fail("%q is not a date-time", str)
			}
		case "oneOf", "anyOf", "allOf":
			n := 0
			for _, sub := range arg.([]any) {
				if passes(sub) {
					n++
				}
			}
			if all := len(arg.([]any)); kw == "oneOf" && n != 1 || kw == "anyOf" && n == 0 || kw == "allOf" && n != all {
				fail("matches %d of %s", n, kw)
			}
		case "not":
			if passes(arg) {
				fail("matches a schema it must not")
			}
		case "if":
			if branch, ok := sc["then"]; ok && passes(arg) {
				s.check(file, branch, v, at, errs)
			} else if branch, ok := sc["else"]; ok && !passes(arg) {
				s.check(file, branch, v, at, errs)
			}
		default:
			fail("unsupported schema keyword %q", kw)
		}
	}
}

func jsonType(v any, t string) bool {
	switch v := v.(type) {
	case nil:
		return t == "null"
	case bool:
		return t == "boolean"
	case string:
		return t == "string"
	case float64:
		return t == "number" || t == "integer" && v == math.Trunc(v)
	case []any:
		return t == "array"
	case map[string]any:
		return t == "object"
	}
	return false
}
