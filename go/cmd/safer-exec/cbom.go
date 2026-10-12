package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// cbomDoc is a CycloneDX CBOM. It uses only fields that CycloneDX 1.6 and 1.7
// share, so it validates against both schemas (cbom_test.go checks this).
type cbomDoc struct {
	BomFormat    string           `json:"bomFormat"`
	SpecVersion  string           `json:"specVersion"`
	Version      int              `json:"version"`
	Metadata     *cbomMetadata    `json:"metadata,omitempty"`
	Components   []cbomComponent  `json:"components,omitempty"`
	Dependencies []cbomDependency `json:"dependencies,omitempty"`
}

type cbomMetadata struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Tools     *cbomTools `json:"tools,omitempty"`
}

type cbomTools struct {
	Components []cbomComponent `json:"components"`
}

type cbomComponent struct {
	Type             string           `json:"type"`
	BomRef           string           `json:"bom-ref,omitempty"`
	Name             string           `json:"name"`
	Version          string           `json:"version,omitempty"`
	CryptoProperties *cbomCryptoProps `json:"cryptoProperties,omitempty"`
	Evidence         *cbomEvidence    `json:"evidence,omitempty"`
}

type cbomEvidence struct {
	Occurrences []cbomOccurrence `json:"occurrences"`
}

type cbomOccurrence struct {
	Location string `json:"location"`
}

type cbomCryptoProps struct {
	AssetType           string          `json:"assetType"`
	AlgorithmProperties *cbomAlgoProps  `json:"algorithmProperties,omitempty"`
	ProtocolProperties  *cbomProtoProps `json:"protocolProperties,omitempty"`
	OID                 string          `json:"oid,omitempty"`
}

type cbomAlgoProps struct {
	Primitive              string   `json:"primitive,omitempty"`
	ParameterSetIdentifier string   `json:"parameterSetIdentifier,omitempty"`
	Mode                   string   `json:"mode,omitempty"`
	CryptoFunctions        []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel int      `json:"classicalSecurityLevel,omitempty"`
	// NistQuantumSecurityLevel is set for ML-KEM (ML-KEM-512 is level 1,
	// -768 level 3, -1024 level 5).
	NistQuantumSecurityLevel int `json:"nistQuantumSecurityLevel,omitempty"`
}

type cbomProtoProps struct {
	Type         string            `json:"type"`
	Version      string            `json:"version,omitempty"`
	CipherSuites []cbomCipherSuite `json:"cipherSuites,omitempty"`
}

// cbomCipherSuite lists the algorithms a suite was negotiated with, by
// bom-ref: its cipher and hash, and the key-exchange group and server key of
// the connections that used it.
type cbomCipherSuite struct {
	Name        string   `json:"name"`
	Algorithms  []string `json:"algorithms,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
}

// cbomDependency records the algorithms and protocols a crypto library was
// seen providing.
type cbomDependency struct {
	Ref      string   `json:"ref"`
	Provides []string `json:"provides,omitempty"`
}

// algorithmOIDs maps the names the CBOM gives algorithms (CycloneDX's naming:
// AES-128-GCM, SHA-256, ML-KEM-768) to their OIDs. The key families (RSA,
// ECDSA, ...) carry the OID of their public-key algorithm. A TLS hybrid group
// such as X25519MLKEM768 has no OID of its own and is recorded as its two
// halves.
var algorithmOIDs = map[string]string{
	"AES":               "2.16.840.1.101.3.4.1", // a traced operation of unknown key size and mode
	"AES-128-CBC":       "2.16.840.1.101.3.4.1.2",
	"AES-128-GCM":       "2.16.840.1.101.3.4.1.6",
	"AES-128-CCM":       "2.16.840.1.101.3.4.1.7",
	"AES-192-CBC":       "2.16.840.1.101.3.4.1.22",
	"AES-192-GCM":       "2.16.840.1.101.3.4.1.26",
	"AES-192-CCM":       "2.16.840.1.101.3.4.1.27",
	"AES-256-CBC":       "2.16.840.1.101.3.4.1.42",
	"AES-256-GCM":       "2.16.840.1.101.3.4.1.46",
	"AES-256-CCM":       "2.16.840.1.101.3.4.1.47",
	"ChaCha20-Poly1305": "1.2.840.113549.1.9.16.3.18",
	"3DES-CBC":          "1.2.840.113549.3.7",
	"MD5":               "1.2.840.113549.2.5",
	"SHA-1":             "1.3.14.3.2.26",
	"SHA-224":           "2.16.840.1.101.3.4.2.4",
	"SHA-256":           "2.16.840.1.101.3.4.2.1",
	"SHA-384":           "2.16.840.1.101.3.4.2.2",
	"SHA-512":           "2.16.840.1.101.3.4.2.3",
	"x25519":            "1.3.101.110",
	"x448":              "1.3.101.111",
	"secp256r1":         "1.2.840.10045.3.1.7",
	"secp384r1":         "1.3.132.0.34",
	"secp521r1":         "1.3.132.0.35",
	"brainpoolP256r1":   "1.3.36.3.3.2.8.1.1.7",
	"brainpoolP384r1":   "1.3.36.3.3.2.8.1.1.11",
	"brainpoolP512r1":   "1.3.36.3.3.2.8.1.1.13",
	"ML-KEM-512":        "2.16.840.1.101.3.4.4.1",
	"ML-KEM-768":        "2.16.840.1.101.3.4.4.2",
	"ML-KEM-1024":       "2.16.840.1.101.3.4.4.3",
	"RSA":               "1.2.840.113549.1.1.1",
	"ECDSA":             "1.2.840.10045.2.1",
	"Ed25519":           "1.3.101.112",
	"Ed448":             "1.3.101.113",
	"DSA":               "1.2.840.10040.4.1",
	"DH":                "1.2.840.113549.1.3.1", // PKCS #3 dhKeyAgreement, for the ffdhe groups and TLS 1.2 DHE
}

// curveSecurityLevels is the classical security, in bits, of each curve.
var curveSecurityLevels = map[string]int{
	"x25519": 128, "x448": 224, "secp256r1": 128, "secp384r1": 192, "secp521r1": 256,
	"brainpoolP256r1": 128, "brainpoolP384r1": 192, "brainpoolP512r1": 256,
}

// cbomModes and cbomFunctions are the closed enums of algorithmProperties.
var (
	cbomModes     = []string{"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"}
	cbomFunctions = []string{"generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive", "sign", "verify", "encapsulate", "decapsulate"}
)

// cbomAlgorithm is an algorithm component before it gets its bom-ref. Its
// OID defaults to algorithmOIDs[name].
type cbomAlgorithm struct {
	name  string
	oid   string
	props cbomAlgoProps
}

// cbomBuilder collects components, merging an algorithm seen more than once.
type cbomBuilder struct {
	doc      cbomDoc
	index    map[string]int
	provides map[string][]string
}

func (b *cbomBuilder) add(c cbomComponent) string {
	if i, ok := b.index[c.BomRef]; ok {
		have := b.doc.Components[i].CryptoProperties
		if have != nil && have.AlgorithmProperties != nil && c.CryptoProperties != nil && c.CryptoProperties.AlgorithmProperties != nil {
			for _, f := range c.CryptoProperties.AlgorithmProperties.CryptoFunctions {
				if !slices.Contains(have.AlgorithmProperties.CryptoFunctions, f) {
					have.AlgorithmProperties.CryptoFunctions = append(have.AlgorithmProperties.CryptoFunctions, f)
				}
			}
		}
		return c.BomRef
	}
	b.index[c.BomRef] = len(b.doc.Components)
	b.doc.Components = append(b.doc.Components, c)
	return c.BomRef
}

// algorithm adds a and returns its bom-ref, crypto/algorithm/<name>@<oid>.
func (b *cbomBuilder) algorithm(a cbomAlgorithm) string {
	oid := a.oid
	if oid == "" {
		oid = algorithmOIDs[a.name]
	}
	ref := "crypto/algorithm/" + url.PathEscape(a.name)
	if oid != "" {
		ref += "@" + oid
	}
	props := a.props
	props.CryptoFunctions = slices.DeleteFunc(slices.Clone(props.CryptoFunctions), func(f string) bool {
		return !slices.Contains(cbomFunctions, f)
	})
	return b.add(cbomComponent{
		Type:   "cryptographic-asset",
		BomRef: ref,
		Name:   a.name,
		CryptoProperties: &cbomCryptoProps{
			AssetType:           "algorithm",
			AlgorithmProperties: &props,
			OID:                 oid,
		},
	})
}

// library adds a crypto library as a library component and returns its
// bom-ref, crypto/library/<name>@<version>.
func (b *cbomBuilder) library(name, version, path string) string {
	ref := "crypto/library/" + url.PathEscape(name)
	if version != "" {
		ref += "@" + url.PathEscape(version)
	}
	if i, ok := b.index[ref]; ok {
		if c := &b.doc.Components[i]; path != "" && c.Evidence != nil && !slices.Contains(c.Evidence.Occurrences, cbomOccurrence{Location: path}) {
			c.Evidence.Occurrences = append(c.Evidence.Occurrences, cbomOccurrence{Location: path})
		}
		return ref
	}
	c := cbomComponent{Type: "library", BomRef: ref, Name: name, Version: version}
	if path != "" {
		c.Evidence = &cbomEvidence{Occurrences: []cbomOccurrence{{Location: path}}}
	}
	return b.add(c)
}

func (b *cbomBuilder) provide(libRef string, refs ...string) {
	for _, r := range refs {
		if !slices.Contains(b.provides[libRef], r) {
			b.provides[libRef] = append(b.provides[libRef], r)
		}
	}
}

// buildCBOM turns a run's crypto observations into a CBOM: the crypto
// libraries, the algorithms of every negotiated suite (cipher, hash,
// key-exchange group, server key) and of every traced operation, and one
// protocol component per TLS version listing its suites.
func buildCBOM(r *config.CryptoResult) cbomDoc {
	b := &cbomBuilder{
		doc: cbomDoc{
			BomFormat:   "CycloneDX",
			SpecVersion: "1.7",
			Version:     1,
			Metadata: &cbomMetadata{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Tools:     &cbomTools{Components: []cbomComponent{{Type: "application", Name: "safer-exec", Version: version}}},
			},
		},
		index:    map[string]int{},
		provides: map[string][]string{},
	}
	libRefs := map[string]string{}
	for _, lib := range r.Libraries {
		ref := b.library(lib.Name, lib.Version, lib.Path)
		if _, ok := libRefs[lib.Name]; !ok {
			libRefs[lib.Name] = ref
		}
	}

	type protocol struct {
		component cbomComponent
		suites    map[string]int
	}
	var protocols []*protocol
	byVersion := map[string]*protocol{}
	for _, c := range r.Ciphers {
		var refs []string
		addRef := func(ref string) {
			if !slices.Contains(refs, ref) {
				refs = append(refs, ref)
			}
		}
		if a, ok := bulkCipher(c); ok {
			addRef(b.algorithm(a))
		}
		if a, ok := hashAlgorithm(c.Hash); ok {
			addRef(b.algorithm(a))
		}
		for _, a := range groupAlgorithms(c.Group) {
			addRef(b.algorithm(a))
		}
		if c.ServerKey != "" {
			addRef(b.algorithm(serverKeyAlgorithm(c.ServerKey)))
		}

		var protoRef string
		if c.Protocol != "" {
			p := byVersion[c.Protocol]
			if p == nil {
				v := strings.TrimPrefix(c.Protocol, "TLSv")
				p = &protocol{
					component: cbomComponent{
						Type:    "cryptographic-asset",
						BomRef:  "crypto/protocol/tls@" + url.PathEscape(v),
						Name:    c.Protocol,
						Version: v,
						CryptoProperties: &cbomCryptoProps{
							AssetType:          "protocol",
							ProtocolProperties: &cbomProtoProps{Type: "tls", Version: v},
						},
					},
					suites: map[string]int{},
				}
				byVersion[c.Protocol] = p
				protocols = append(protocols, p)
			}
			protoRef = p.component.BomRef
			name := c.IANAName
			if name == "" {
				name = c.Name
			}
			props := p.component.CryptoProperties.ProtocolProperties
			i, ok := p.suites[name]
			if !ok {
				i = len(props.CipherSuites)
				p.suites[name] = i
				suite := cbomCipherSuite{Name: name}
				if c.IANAID != 0 {
					suite.Identifiers = []string{fmt.Sprintf("0x%02X", c.IANAID>>8), fmt.Sprintf("0x%02X", c.IANAID&0xff)}
				}
				props.CipherSuites = append(props.CipherSuites, suite)
			}
			for _, ref := range refs {
				if !slices.Contains(props.CipherSuites[i].Algorithms, ref) {
					props.CipherSuites[i].Algorithms = append(props.CipherSuites[i].Algorithms, ref)
				}
			}
		}

		// The Linux tracer names the library that negotiated the suite; the
		// egress proxy cannot tell.
		if c.Library != "" {
			libRef, ok := libRefs[c.Library]
			if !ok {
				libRef = b.library(c.Library, c.LibraryVersion, "")
				libRefs[c.Library] = libRef
			}
			b.provide(libRef, refs...)
			if protoRef != "" {
				b.provide(libRef, protoRef)
			}
		}
	}

	for _, op := range r.Operations {
		a, ok := hashAlgorithm(op.Algorithm)
		if !ok {
			a = cbomAlgorithm{name: op.Algorithm, props: cbomAlgoProps{Primitive: "unknown"}}
			if strings.HasPrefix(strings.ToUpper(op.Algorithm), "AES") {
				a.props.Primitive = "block-cipher"
			}
		}
		a.props.CryptoFunctions = []string{op.Type}
		b.algorithm(a)
	}

	for _, p := range protocols {
		b.add(p.component)
	}
	for _, c := range b.doc.Components {
		if refs := b.provides[c.BomRef]; len(refs) > 0 {
			b.doc.Dependencies = append(b.doc.Dependencies, cbomDependency{Ref: c.BomRef, Provides: refs})
		}
	}
	return b.doc
}

// bulkCipher is the symmetric cipher of a suite (AES-128-GCM).
func bulkCipher(c config.CipherInfo) (cbomAlgorithm, bool) {
	enc := strings.ToUpper(c.Encryption)
	mode := strings.ToUpper(c.Mode)
	if mode == "CCM8" {
		mode = "CCM"
	}
	bits := c.EncryptionBits
	var a cbomAlgorithm
	switch enc {
	case "", "NULL":
		return a, false
	case "CHACHA20":
		return cbomAlgorithm{name: "ChaCha20-Poly1305", props: cbomAlgoProps{
			Primitive: "ae", ParameterSetIdentifier: "256", CryptoFunctions: []string{"encrypt", "decrypt"}, ClassicalSecurityLevel: 256,
		}}, true
	case "3DES":
		a.name = "3DES"
		bits = 112
	case "AES", "CAMELLIA", "ARIA", "RC4":
		if bits == 0 {
			bits = 128
		}
		a.name = enc + "-" + strconv.Itoa(bits)
		a.props.ParameterSetIdentifier = strconv.Itoa(bits)
	default:
		a.name = enc
	}
	if mode != "" && mode != "POLY1305" {
		a.name += "-" + mode
	}
	switch {
	case mode == "GCM" || mode == "CCM":
		a.props.Primitive = "ae"
	case enc == "RC4":
		a.props.Primitive = "stream-cipher"
	default:
		a.props.Primitive = "block-cipher"
	}
	if m := strings.ToLower(mode); slices.Contains(cbomModes, m) {
		a.props.Mode = m
	}
	a.props.CryptoFunctions = []string{"encrypt", "decrypt"}
	a.props.ClassicalSecurityLevel = bits
	return a, true
}

// hashAlgorithm names a hash as the CBOM does (SHA-256) from a suite's hash
// ("SHA256", "SHA" for SHA-1) or a traced operation's algorithm.
func hashAlgorithm(h string) (cbomAlgorithm, bool) {
	var name string
	switch u := strings.ReplaceAll(strings.ToUpper(h), "-", ""); u {
	case "MD5":
		name = "MD5"
	case "SHA", "SHA1":
		name = "SHA-1"
	case "SHA224", "SHA256", "SHA384", "SHA512":
		name = "SHA-" + u[3:]
	default:
		return cbomAlgorithm{}, false
	}
	a := cbomAlgorithm{name: name, props: cbomAlgoProps{Primitive: "hash", CryptoFunctions: []string{"digest"}}}
	if bits, ok := strings.CutPrefix(name, "SHA-"); ok && bits != "1" {
		a.props.ParameterSetIdentifier = bits
	}
	return a, true
}

// groupAlgorithms names the algorithms of a TLS key-exchange group. A hybrid
// is its classical curve and ML-KEM; the pre-standard Kyber draft has no OID
// and is recorded as its curve alone.
func groupAlgorithms(group string) []cbomAlgorithm {
	if group == "" {
		return nil
	}
	var out []cbomAlgorithm
	classical := group
	for _, level := range []struct {
		params string
		nist   int
	}{{"512", 1}, {"768", 3}, {"1024", 5}} {
		if rest, ok := strings.CutSuffix(group, "MLKEM"+level.params); ok {
			classical = rest
			out = append(out, cbomAlgorithm{name: "ML-KEM-" + level.params, props: cbomAlgoProps{
				Primitive: "kem", ParameterSetIdentifier: level.params,
				CryptoFunctions:          []string{"keygen", "encapsulate", "decapsulate"},
				NistQuantumSecurityLevel: level.nist,
			}})
		}
	}
	if rest, ok := strings.CutSuffix(classical, "Kyber768Draft00"); ok {
		classical = rest
	}
	if classical == "" {
		return out
	}
	name := strings.TrimSuffix(classical, "tls13")
	if lower := strings.ToLower(name); curveSecurityLevels[lower] != 0 {
		name = lower
	}
	curve := cbomAlgorithm{name: name, props: cbomAlgoProps{
		Primitive: "key-agree", CryptoFunctions: []string{"keygen"}, ClassicalSecurityLevel: curveSecurityLevels[name],
	}}
	if bits, ok := strings.CutPrefix(name, "ffdhe"); ok {
		curve.oid, curve.props.ParameterSetIdentifier = algorithmOIDs["DH"], bits
	} else if bits, ok := strings.CutPrefix(name, "DH-"); ok {
		curve.oid, curve.props.ParameterSetIdentifier = algorithmOIDs["DH"], bits
	}
	return append([]cbomAlgorithm{curve}, out...)
}

// serverKeyAlgorithm describes a server certificate key ("RSA-2048",
// "ECDSA-P-256", "Ed25519"), which signs the TLS 1.2 key exchange.
func serverKeyAlgorithm(key string) cbomAlgorithm {
	family, params, _ := strings.Cut(key, "-")
	return cbomAlgorithm{name: key, oid: algorithmOIDs[family], props: cbomAlgoProps{
		Primitive: "signature", ParameterSetIdentifier: params, CryptoFunctions: []string{"verify"},
	}}
}

// writeCBOMFile writes the CBOM of a run's crypto observations to path.
func writeCBOMFile(path string, cryptoResult *config.CryptoResult) {
	data, err := json.MarshalIndent(buildCBOM(cryptoResult), "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: cbom marshal: %v\n", err)
		return
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: cbom write: %v\n", err)
	}
}
