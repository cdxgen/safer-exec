package tlsobserve

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
)

// VersionName returns the OpenSSL-style name of a protocol version
// ("TLSv1.2"), the form the Linux crypto tracer reports.
func VersionName(v uint16) string {
	switch v {
	case 0x0300:
		return "SSLv3"
	case 0x0301:
		return "TLSv1"
	case 0x0302:
		return "TLSv1.1"
	case 0x0303:
		return "TLSv1.2"
	case 0x0304:
		return "TLSv1.3"
	}
	return fmt.Sprintf("0x%04X", v)
}

// groups maps TLS supported-group code points to their IANA names.
var groups = map[uint16]string{
	0x0017: "secp256r1",
	0x0018: "secp384r1",
	0x0019: "secp521r1",
	0x001A: "brainpoolP256r1",
	0x001B: "brainpoolP384r1",
	0x001C: "brainpoolP512r1",
	0x001D: "x25519",
	0x001E: "x448",
	0x001F: "brainpoolP256r1tls13",
	0x0020: "brainpoolP384r1tls13",
	0x0021: "brainpoolP512r1tls13",
	0x0100: "ffdhe2048",
	0x0101: "ffdhe3072",
	0x0102: "ffdhe4096",
	0x0103: "ffdhe6144",
	0x0104: "ffdhe8192",
	0x0200: "MLKEM512",
	0x0201: "MLKEM768",
	0x0202: "MLKEM1024",
	0x11EB: "SecP256r1MLKEM768",
	0x11EC: "X25519MLKEM768",
	0x11ED: "SecP384r1MLKEM1024",
	0x6399: "X25519Kyber768Draft00",
}

// GroupName returns the IANA name of a key-exchange group, or its code point
// in hex when unknown.
func GroupName(g uint16) string {
	if n, ok := groups[g]; ok {
		return n
	}
	return fmt.Sprintf("0x%04X", g)
}

// GroupPostQuantum reports whether a group includes a post-quantum KEM, alone
// or in a hybrid with a classical curve.
func GroupPostQuantum(g uint16) bool {
	n := groups[g]
	return strings.Contains(n, "MLKEM") || strings.Contains(n, "Kyber")
}

// GroupKeyExchange names the key-exchange family of a group, for TLS 1.3
// suites, which do not encode it.
func GroupKeyExchange(g uint16) string {
	n, ok := groups[g]
	switch {
	case !ok:
		return ""
	case strings.HasPrefix(n, "MLKEM"):
		return "ML-KEM"
	case GroupPostQuantum(g):
		return "ECDHE+ML-KEM"
	case strings.HasPrefix(n, "ffdhe"):
		return "DHE"
	}
	return "ECDHE"
}

// extraSuites names suites crypto/tls does not know (it implements no DHE or
// CCM suite).
var extraSuites = map[uint16]string{
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xC09C: "TLS_RSA_WITH_AES_128_CCM",
	0xC09D: "TLS_RSA_WITH_AES_256_CCM",
	0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
	0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
	0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",
}

// SuiteInfo is a cipher suite decomposed into its algorithms, in the field
// conventions of the Linux crypto tracer.
type SuiteInfo struct {
	// Name is the IANA name, or the code point in hex when unknown.
	Name string
	// Known is false when the suite is not in the registry.
	Known bool
	// KeyExchange and Authentication are empty for TLS 1.3 suites, which
	// negotiate them separately.
	KeyExchange    string
	Authentication string
	Encryption     string
	EncryptionBits int
	Mode           string
	Hash           string
}

// Suite decomposes an IANA cipher suite.
func Suite(id uint16) SuiteInfo {
	name, ok := extraSuites[id]
	if !ok {
		name = tls.CipherSuiteName(id)
		ok = strings.HasPrefix(name, "TLS_")
	}
	s := SuiteInfo{Name: name, Known: ok}
	if !ok {
		return s
	}
	rest := strings.TrimPrefix(name, "TLS_")
	cipher := rest
	if kxAuth, after, found := strings.Cut(rest, "_WITH_"); found {
		cipher = after
		parts := strings.Split(kxAuth, "_")
		s.KeyExchange = parts[0]
		switch {
		case len(parts) > 1:
			s.Authentication = parts[1]
		case parts[0] == "RSA" || parts[0] == "PSK":
			s.Authentication = parts[0]
		}
	}
	toks := strings.Split(cipher, "_")
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch t {
		case "AES", "CAMELLIA", "ARIA", "SEED", "RC4", "DES":
			s.Encryption = t
			if i+1 < len(toks) {
				if bits, err := strconv.Atoi(toks[i+1]); err == nil {
					s.EncryptionBits = bits
					i++
				}
			}
			if s.EncryptionBits == 0 {
				s.EncryptionBits = map[string]int{"DES": 56, "SEED": 128}[t]
			}
		case "3DES":
			s.Encryption, s.EncryptionBits = "3DES", 112
		case "CHACHA20":
			s.Encryption, s.EncryptionBits = "CHACHA20", 256
		case "NULL":
			s.Encryption = "NULL"
		case "GCM", "CBC", "POLY1305":
			s.Mode = t
		case "CCM":
			s.Mode = "CCM"
			if i+1 < len(toks) && toks[i+1] == "8" {
				s.Mode = "CCM8"
				i++
			}
		case "SHA":
			s.Hash = "SHA1"
		case "SHA256", "SHA384", "SHA512", "MD5":
			s.Hash = t
		}
	}
	return s
}
