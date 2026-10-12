package dlltrace

import "strings"

// cryptoModules names the cryptographic libraries recognized by file name.
// Windows' own modules are matched exactly; the portable libraries that ship
// as DLLs are matched by name prefix, since their names carry a version or
// architecture suffix (libcrypto-3-x64.dll).
var cryptoModules = map[string]string{
	"bcrypt.dll":           "Windows CNG (bcrypt)",
	"bcryptprimitives.dll": "Windows CNG primitives (SymCrypt)",
	"symcrypt.dll":         "SymCrypt",
	"ncrypt.dll":           "Windows CNG key storage (ncrypt)",
	"ncryptprov.dll":       "Microsoft Software Key Storage Provider",
	"ncryptsslp.dll":       "Windows CNG SSL provider",
	"schannel.dll":         "Windows Schannel",
	"crypt32.dll":          "Windows CryptoAPI (crypt32)",
	"cryptsp.dll":          "Windows CryptoAPI (cryptsp)",
	"rsaenh.dll":           "Microsoft Enhanced RSA and AES Cryptographic Provider",
	"dssenh.dll":           "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider",
	"libeay32.dll":         "OpenSSL",
	"ssleay32.dll":         "OpenSSL",
	"nss3.dll":             "NSS",
	"softokn3.dll":         "NSS",
	"freebl3.dll":          "NSS",
	"freeblpriv3.dll":      "NSS",
}

var cryptoPrefixes = []struct{ prefix, name string }{
	{"libcrypto", "OpenSSL"},
	{"libssl", "OpenSSL"},
	{"libgnutls", "GnuTLS"},
	{"libnettle", "Nettle"},
	{"libhogweed", "Nettle"},
	{"libgcrypt", "Libgcrypt"},
	{"libmbedcrypto", "Mbed TLS"},
	{"libmbedtls", "Mbed TLS"},
	{"mbedcrypto", "Mbed TLS"},
	{"mbedtls", "Mbed TLS"},
	{"wolfssl", "wolfSSL"},
	{"libwolfssl", "wolfSSL"},
	{"libsodium", "libsodium"},
	{"botan", "Botan"},
	{"cryptopp", "Crypto++"},
}

// CryptoLibrary returns the name of the cryptographic library a loaded
// module belongs to, or "" when its file name is not a known one. path may
// use either separator.
func CryptoLibrary(path string) string {
	base := strings.ToLower(path[strings.LastIndexAny(path, `\/`)+1:])
	if !strings.HasSuffix(base, ".dll") {
		return ""
	}
	if name, ok := cryptoModules[base]; ok {
		return name
	}
	stem := strings.TrimSuffix(base, ".dll")
	for _, p := range cryptoPrefixes {
		if stem == p.prefix || strings.HasPrefix(stem, p.prefix+"-") || strings.HasPrefix(stem, p.prefix+".") || strings.HasPrefix(stem, p.prefix+"_") {
			return p.name
		}
	}
	return ""
}
