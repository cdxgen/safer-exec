package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// cbomDoc is a minimal CycloneDX CBOM document structure.
type cbomDoc struct {
	BomFormat   string          `json:"bomFormat"`
	SpecVersion string          `json:"specVersion"`
	Version     int             `json:"version"`
	Components  []cbomComponent `json:"components,omitempty"`
}

type cbomComponent struct {
	Type             string           `json:"type"`
	Name             string           `json:"name"`
	Version          string           `json:"version,omitempty"`
	CryptoProperties *cbomCryptoProps `json:"cryptoProperties,omitempty"`
}

type cbomCryptoProps struct {
	AssetType                  string            `json:"assetType"`
	AlgorithmProperties        *cbomAlgoProps    `json:"algorithmProperties,omitempty"`
	RelatedCryptoMaterialProps *cbomRelatedProps `json:"relatedCryptoMaterialProperties,omitempty"`
	ProtocolProperties         *cbomProtoProps   `json:"protocolProperties,omitempty"`
}

type cbomAlgoProps struct {
	Primitive              string   `json:"primitive,omitempty"`
	ParameterSetIdentifier string   `json:"parameterSetIdentifier,omitempty"`
	Mode                   string   `json:"mode,omitempty"`
	ExecutionEnvironment   string   `json:"executionEnvironment,omitempty"`
	ImplementationPlatform string   `json:"implementationPlatform,omitempty"`
	CryptoFunctions        []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel int      `json:"classicalSecurityLevel,omitempty"`
	// NistQuantumSecurityLevel is set for post-quantum KEMs (ML-KEM-512 is
	// level 1, -768 level 3, -1024 level 5).
	NistQuantumSecurityLevel int `json:"nistQuantumSecurityLevel,omitempty"`
}

type cbomRelatedProps struct {
	Type string `json:"type"`
}

type cbomProtoProps struct {
	Type         string            `json:"type"`
	Version      string            `json:"version,omitempty"`
	CipherSuites []cbomCipherSuite `json:"cipherSuites,omitempty"`
}

type cbomCipherSuite struct {
	Name       string   `json:"name"`
	Algorithms []string `json:"algorithms,omitempty"`
}

// writeCBOMFile writes a minimal CycloneDX CBOM JSON document to the given path.
func writeCBOMFile(path string, cryptoResult *config.CryptoResult) {
	doc := cbomDoc{
		BomFormat:   "CycloneDX",
		SpecVersion: "1.7",
		Version:     1,
	}

	for _, lib := range cryptoResult.Libraries {
		ver := lib.Version
		if ver == "" {
			ver = "unknown"
		}
		doc.Components = append(doc.Components, cbomComponent{
			Type:    "cryptographic-asset",
			Name:    lib.Name,
			Version: ver,
			CryptoProperties: &cbomCryptoProps{
				AssetType: "related-crypto-material",
				RelatedCryptoMaterialProps: &cbomRelatedProps{
					Type: "library",
				},
			},
		})
	}

	for _, c := range cryptoResult.Ciphers {
		funcs := []string{"encrypt"}
		if c.Mode != "" {
			funcs = append(funcs, "decrypt")
		}
		doc.Components = append(doc.Components, cbomComponent{
			Type:    "cryptographic-asset",
			Name:    c.Name,
			Version: c.Protocol,
			CryptoProperties: &cbomCryptoProps{
				AssetType: "algorithm",
				AlgorithmProperties: &cbomAlgoProps{
					Primitive:              algoPrimitive(c),
					ParameterSetIdentifier: c.Hash,
					Mode:                   c.Mode,
					ExecutionEnvironment:   c.Library,
					ImplementationPlatform: c.Library,
					CryptoFunctions:        funcs,
					ClassicalSecurityLevel: c.Bits,
				},
			},
		})
	}

	// Key-exchange groups and server keys the egress proxy saw in TLS
	// handshakes (post-quantum hybrids such as X25519MLKEM768 included).
	seenAlgos := make(map[string]bool)
	for _, c := range cryptoResult.Ciphers {
		if c.Group != "" && !seenAlgos["group|"+c.Group] {
			seenAlgos["group|"+c.Group] = true
			props := &cbomAlgoProps{Primitive: "key-agree", CryptoFunctions: []string{"keygen", "keyagree"}}
			if c.PostQuantum {
				props.Primitive = "kem"
				props.CryptoFunctions = []string{"keygen", "encapsulate", "decapsulate"}
				props.NistQuantumSecurityLevel = mlkemLevel(c.Group)
			}
			doc.Components = append(doc.Components, cbomComponent{
				Type: "cryptographic-asset",
				Name: c.Group,
				CryptoProperties: &cbomCryptoProps{
					AssetType:           "algorithm",
					AlgorithmProperties: props,
				},
			})
		}
		if c.ServerKey != "" && !seenAlgos["key|"+c.ServerKey] {
			seenAlgos["key|"+c.ServerKey] = true
			doc.Components = append(doc.Components, cbomComponent{
				Type: "cryptographic-asset",
				Name: c.ServerKey,
				CryptoProperties: &cbomCryptoProps{
					AssetType: "algorithm",
					AlgorithmProperties: &cbomAlgoProps{
						Primitive:       "signature",
						CryptoFunctions: []string{"verify"},
					},
				},
			})
		}
	}

	seenProtocols := make(map[string]bool)
	for _, c := range cryptoResult.Ciphers {
		if c.Protocol == "" {
			continue
		}
		protoKey := c.Protocol
		if seenProtocols[protoKey] {
			continue
		}
		seenProtocols[protoKey] = true

		protoVersion := c.Protocol
		if strings.HasPrefix(protoVersion, "TLSv") {
			protoVersion = strings.TrimPrefix(protoVersion, "TLSv")
		}

		var suites []cbomCipherSuite
		for _, o := range cryptoResult.Ciphers {
			if o.Protocol == c.Protocol {
				name := o.IANAName
				if name == "" {
					name = o.Name
				}
				var algs []string
				if o.KeyExchange != "" && o.KeyExchange != "inline" {
					algs = append(algs, o.KeyExchange)
				}
				if o.Authentication != "" && o.Authentication != "inline" {
					algs = append(algs, o.Authentication)
				}
				if o.Encryption != "" {
					algs = append(algs, o.Encryption)
				}
				if o.Hash != "" {
					algs = append(algs, o.Hash)
				}
				suites = append(suites, cbomCipherSuite{
					Name:       name,
					Algorithms: algs,
				})
			}
		}

		doc.Components = append(doc.Components, cbomComponent{
			Type:    "cryptographic-asset",
			Name:    c.Protocol,
			Version: protoVersion,
			CryptoProperties: &cbomCryptoProps{
				AssetType: "protocol",
				ProtocolProperties: &cbomProtoProps{
					Type:         "tls",
					Version:      protoVersion,
					CipherSuites: suites,
				},
			},
		})
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: cbom marshal: %v\n", err)
		return
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "safer-exec: cbom write: %v\n", err)
	}
}

// mlkemLevel is the NIST security category of the ML-KEM parameter set in a
// group name.
func mlkemLevel(group string) int {
	switch {
	case strings.Contains(group, "MLKEM1024"):
		return 5
	case strings.Contains(group, "MLKEM768"), strings.Contains(group, "Kyber768"):
		return 3
	case strings.Contains(group, "MLKEM512"):
		return 1
	}
	return 0
}

func algoPrimitive(c config.CipherInfo) string {
	switch {
	case c.Mode == "GCM" || c.Mode == "CCM" || c.Mode == "POLY1305":
		return "aead"
	case c.Encryption != "":
		return "block-cipher"
	case c.KeyExchange != "":
		return "key-agree"
	default:
		return "other"
	}
}
