// Package httptrace — cipher name parsing and IANA registry mapping.
// Maps human-readable OpenSSL/GnuTLS cipher names to decomposed algorithm
// properties for CBOM generation.
package httptrace

import (
	"strings"
)

// DecomposeCipherName parses an OpenSSL-style cipher suite name into its
// constituent algorithms. Handles TLS 1.3 suite names and DH/ECDHE variants.
//
// Examples:
//
//	"ECDHE-RSA-AES256-GCM-SHA384" → kx=ECDHE, auth=RSA, enc=AES-256-GCM, hash=SHA384
//	"TLS_AES_256_GCM_SHA384"      → enc=AES-256-GCM, hash=SHA384
//	"AES256-GCM-SHA384"           → enc=AES-256-GCM, hash=SHA384
//	"ECDHE-ECDSA-CHACHA20-POLY1305" → kx=ECDHE, auth=ECDSA, enc=CHACHA20, mode=POLY1305
func DecomposeCipherName(name string) CipherDecomposed {
	d := CipherDecomposed{RawName: name}
	if name == "" {
		return d
	}

	upper := strings.ToUpper(name)

	// TLS 1.3 format: "TLS_AES_256_GCM_SHA384"
	if strings.HasPrefix(upper, "TLS_") {
		d.Protocol = "TLSv1.3"
		d.KeyExchange = "inline"
		d.Authentication = "inline"
		rest := upper[4:]
		if idx := strings.Index(rest, "_WITH_"); idx >= 0 {
			rest = rest[:idx]
		}
		parseEncHash(rest, &d)
		return d
	}

	// Detect key exchange prefix
	for _, kx := range []string{"ECDHE-", "DHE-", "ECDH-", "DH-", "RSA-", "PSK-", "SRP-"} {
		if strings.HasPrefix(upper, kx) {
			d.KeyExchange = strings.TrimSuffix(kx, "-")
			upper = upper[len(kx):]
			break
		}
	}

	// Detect auth after key exchange
	for _, auth := range []string{"ECDSA-", "RSA-", "DSS-", "ED25519-", "ED448-"} {
		if strings.HasPrefix(upper, auth) {
			d.Authentication = strings.TrimSuffix(auth, "-")
			upper = upper[len(auth):]
			break
		}
	}

	// The rest is encryption[_mode][-hash]
	parseRemaining(upper, &d)

	return d
}

func parseRemaining(s string, d *CipherDecomposed) {
	// Remove trailing "-WITH-..." suffix if present
	if idx := strings.Index(s, "-WITH-"); idx >= 0 {
		s = s[:idx]
	}

	parts := strings.Split(s, "-")
	if len(parts) == 0 {
		return
	}

	// Detect encryption algorithm
	encAlgos := map[string]string{
		"AES128": "AES", "AES256": "AES", "AES192": "AES",
		"AES": "AES", "CAMELLIA128": "CAMELLIA", "CAMELLIA256": "CAMELLIA",
		"CAMELLIA": "CAMELLIA", "SEED": "SEED", "ARIA128": "ARIA",
		"ARIA256": "ARIA", "ARIA": "ARIA",
		"DES": "DES", "3DES": "3DES", "IDEA": "IDEA", "RC2": "RC2",
		"RC4": "RC4", "CHACHA20": "CHACHA20",
	}

	for _, p := range parts {
		if algo, ok := encAlgos[p]; ok {
			d.Encryption = algo
			d.EncryptionBits = extractBits(p)
			if d.EncryptionBits == 0 {
				d.EncryptionBits = defaultBitsForAlgo(algo)
			}
			continue
		}
		// Mode detection
		switch p {
		case "GCM", "CCM", "CCM8":
			d.Mode = p
		case "CBC", "CTR", "OFB", "CFB", "XTS", "OCB":
			d.Mode = p
		case "POLY1305":
			d.Mode = "POLY1305"
		default:
			// Hash/MAC detection
			if isHash(p) {
				d.Hash = p
			}
		}
	}
}

func parseEncHash(s string, d *CipherDecomposed) {
	parts := strings.Split(s, "_")

	encAlgos := map[string]struct {
		algo string
		bits int
	}{
		"AES":      {"AES", 0},
		"CAMELLIA": {"CAMELLIA", 0},
		"ARIA":     {"ARIA", 0},
		"SEED":     {"SEED", 128},
		"CHACHA20": {"CHACHA20", 256},
		"DES":      {"DES", 56},
		"3DES":     {"3DES", 112},
		"RC4":      {"RC4", 128},
	}

	for i := 0; i < len(parts); i++ {
		p := parts[i]
		// Check for encryption algorithm
		for prefix, info := range encAlgos {
			if strings.EqualFold(p, prefix) || strings.HasPrefix(p, prefix) {
				d.Encryption = info.algo
				if info.bits > 0 {
					d.EncryptionBits = info.bits
				} else if len(p) > len(prefix) {
					// Has embedded bit size like "AES256"
					d.EncryptionBits = extractBits(p)
				} else if i+1 < len(parts) && isDigits(parts[i+1]) {
					// Next part is the bit size like "256"
					d.EncryptionBits = parseBitsStr(parts[i+1])
				}
				break
			}
		}
		// Check for mode
		switch p {
		case "GCM", "CCM", "CCM8", "CBC", "CTR", "OFB", "CFB", "XTS", "OCB", "POLY1305":
			d.Mode = p
		default:
			if isHash(p) {
				d.Hash = p
			}
		}
	}

	if d.EncryptionBits == 0 && d.Encryption != "" {
		d.EncryptionBits = 128
	}
}

func parseBitsStr(s string) int {
	switch s {
	case "128":
		return 128
	case "192":
		return 192
	case "256":
		return 256
	case "384":
		return 384
	case "512":
		return 512
	case "40":
		return 40
	case "56":
		return 56
	case "112":
		return 112
	case "168":
		return 168
	default:
		return 0
	}
}

func defaultBitsForAlgo(algo string) int {
	known := map[string]int{
		"CHACHA20": 256,
		"AES":      128,
		"CAMELLIA": 128,
		"ARIA":     128,
		"SEED":     128,
		"DES":      56,
		"3DES":     112,
		"IDEA":     128,
		"RC2":      40,
		"RC4":      128,
	}
	if bits, ok := known[algo]; ok {
		return bits
	}
	return 0
}

func isHash(s string) bool {
	hashes := map[string]bool{
		"SHA1": true, "SHA224": true, "SHA256": true, "SHA384": true,
		"SHA512": true, "MD5": true, "SHA": true,
	}
	return hashes[strings.ToUpper(s)]
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func extractBits(s string) int {
	switch {
	case strings.Contains(s, "256"):
		return 256
	case strings.Contains(s, "384"):
		return 384
	case strings.Contains(s, "192"):
		return 192
	case strings.Contains(s, "128"):
		return 128
	case strings.Contains(s, "40"):
		return 40
	case strings.Contains(s, "56"):
		return 56
	case strings.Contains(s, "112"):
		return 112
	case strings.Contains(s, "168"):
		return 168
	case strings.Contains(s, "512"):
		return 512
	default:
		return 0
	}
}

func knownIANACipher(name string) (uint16, bool) {
	ciphers := map[string]uint16{
		// TLS 1.3
		"TLS_AES_128_GCM_SHA256":       0x1301,
		"TLS_AES_256_GCM_SHA384":       0x1302,
		"TLS_CHACHA20_POLY1305_SHA256": 0x1303,
		"TLS_AES_128_CCM_SHA256":       0x1304,
		"TLS_AES_128_CCM_8_SHA256":     0x1305,
		// TLS 1.2 ECDHE
		"ECDHE-ECDSA-AES128-GCM-SHA256": 0xC02B,
		"ECDHE-ECDSA-AES256-GCM-SHA384": 0xC02C,
		"ECDHE-RSA-AES128-GCM-SHA256":   0xC02F,
		"ECDHE-RSA-AES256-GCM-SHA384":   0xC030,
		"ECDHE-ECDSA-AES128-SHA256":     0xC023,
		"ECDHE-ECDSA-AES256-SHA384":     0xC024,
		"ECDHE-RSA-AES128-SHA256":       0xC027,
		"ECDHE-RSA-AES256-SHA384":       0xC028,
		"ECDHE-ECDSA-CHACHA20-POLY1305": 0xCCA9,
		"ECDHE-RSA-CHACHA20-POLY1305":   0xCCA8,
		// TLS 1.2 DHE
		"DHE-RSA-AES128-GCM-SHA256": 0x009E,
		"DHE-RSA-AES256-GCM-SHA384": 0x009F,
		"DHE-RSA-AES128-SHA256":     0x0067,
		"DHE-RSA-AES256-SHA256":     0x006B,
		// TLS 1.2 RSA
		"AES128-GCM-SHA256": 0x009C,
		"AES256-GCM-SHA384": 0x009D,
		"AES128-SHA256":     0x003C,
		"AES256-SHA256":     0x003D,
	}
	if id, ok := ciphers[strings.ToUpper(name)]; ok {
		return id, true
	}
	return 0, false
}

// CipherDecomposed holds the result of decomposing a cipher suite name into
// its constituent algorithms.
type CipherDecomposed struct {
	RawName        string
	KeyExchange    string
	Authentication string
	Encryption     string
	EncryptionBits int
	Hash           string
	Mode           string
	Protocol       string
}

// IANACipherName converts a human-readable cipher name to the IANA-registered
// name format (e.g. "ECDHE-RSA-AES256-GCM-SHA384" → "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384").
// Returns the original name if no IANA mapping is found.
func IANACipherName(readable string) string {
	known := map[string]string{
		"ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"ECDHE-RSA-AES128-GCM-SHA256":   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"ECDHE-RSA-AES256-GCM-SHA384":   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"ECDHE-ECDSA-AES128-SHA256":     "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		"ECDHE-ECDSA-AES256-SHA384":     "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		"ECDHE-RSA-AES128-SHA256":       "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"ECDHE-RSA-AES256-SHA384":       "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
		"ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		"ECDHE-RSA-CHACHA20-POLY1305":   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		"DHE-RSA-AES128-GCM-SHA256":     "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		"DHE-RSA-AES256-GCM-SHA384":     "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		"DHE-RSA-AES128-SHA256":         "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		"DHE-RSA-AES256-SHA256":         "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
		"AES128-GCM-SHA256":             "TLS_RSA_WITH_AES_128_GCM_SHA256",
		"AES256-GCM-SHA384":             "TLS_RSA_WITH_AES_256_GCM_SHA384",
		"AES128-SHA256":                 "TLS_RSA_WITH_AES_128_CBC_SHA256",
		"AES256-SHA256":                 "TLS_RSA_WITH_AES_256_CBC_SHA256",
	}
	upper := strings.ToUpper(readable)
	if iana, ok := known[upper]; ok {
		return iana
	}
	return readable
}

// CipherNameByID returns the OpenSSL-style cipher suite name for a given 2-byte IANA ID.
func CipherNameByID(id uint16) (string, bool) {
	ciphers := map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0x1304: "TLS_AES_128_CCM_SHA256",
		0x1305: "TLS_AES_128_CCM_8_SHA256",
		0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
		0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
		0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
		0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
		0xC023: "ECDHE-ECDSA-AES128-SHA256",
		0xC024: "ECDHE-ECDSA-AES256-SHA384",
		0xC027: "ECDHE-RSA-AES128-SHA256",
		0xC028: "ECDHE-RSA-AES256-SHA384",
		0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
		0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
		0x009E: "DHE-RSA-AES128-GCM-SHA256",
		0x009F: "DHE-RSA-AES256-GCM-SHA384",
		0x0067: "DHE-RSA-AES128-SHA256",
		0x006B: "DHE-RSA-AES256-SHA256",
		0x009C: "AES128-GCM-SHA256",
		0x009D: "AES256-GCM-SHA384",
		0x003C: "AES128-SHA256",
		0x003D: "AES256-SHA256",
	}
	if name, ok := ciphers[id]; ok {
		return name, true
	}
	return "", false
}
