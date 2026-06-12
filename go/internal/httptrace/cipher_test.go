package httptrace

import (
	"strings"
	"testing"
)

func TestDecomposeCipherName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected CipherDecomposed
	}{
		{
			name:  "TLS 1.3 AES-256-GCM",
			input: "TLS_AES_256_GCM_SHA384",
			expected: CipherDecomposed{
				RawName:        "TLS_AES_256_GCM_SHA384",
				KeyExchange:    "inline",
				Authentication: "inline",
				Encryption:     "AES",
				EncryptionBits: 256,
				Hash:           "SHA384",
				Mode:           "GCM",
				Protocol:       "TLSv1.3",
			},
		},
		{
			name:  "TLS 1.3 AES-128-GCM",
			input: "TLS_AES_128_GCM_SHA256",
			expected: CipherDecomposed{
				RawName:        "TLS_AES_128_GCM_SHA256",
				Protocol:       "TLSv1.3",
				KeyExchange:    "inline",
				Authentication: "inline",
				Encryption:     "AES",
				EncryptionBits: 128,
				Hash:           "SHA256",
				Mode:           "GCM",
			},
		},
		{
			name:  "TLS 1.3 CHACHA20",
			input: "TLS_CHACHA20_POLY1305_SHA256",
			expected: CipherDecomposed{
				RawName:        "TLS_CHACHA20_POLY1305_SHA256",
				Protocol:       "TLSv1.3",
				KeyExchange:    "inline",
				Authentication: "inline",
				Encryption:     "CHACHA20",
				EncryptionBits: 256,
				Hash:           "SHA256",
				Mode:           "POLY1305",
			},
		},
		{
			name:  "ECDHE-RSA-AES256-GCM-SHA384",
			input: "ECDHE-RSA-AES256-GCM-SHA384",
			expected: CipherDecomposed{
				RawName:        "ECDHE-RSA-AES256-GCM-SHA384",
				KeyExchange:    "ECDHE",
				Authentication: "RSA",
				Encryption:     "AES",
				EncryptionBits: 256,
				Hash:           "SHA384",
				Mode:           "GCM",
			},
		},
		{
			name:  "ECDHE-ECDSA-AES128-GCM-SHA256",
			input: "ECDHE-ECDSA-AES128-GCM-SHA256",
			expected: CipherDecomposed{
				RawName:        "ECDHE-ECDSA-AES128-GCM-SHA256",
				KeyExchange:    "ECDHE",
				Authentication: "ECDSA",
				Encryption:     "AES",
				EncryptionBits: 128,
				Hash:           "SHA256",
				Mode:           "GCM",
			},
		},
		{
			name:  "ECDHE-ECDSA-CHACHA20-POLY1305",
			input: "ECDHE-ECDSA-CHACHA20-POLY1305",
			expected: CipherDecomposed{
				RawName:        "ECDHE-ECDSA-CHACHA20-POLY1305",
				KeyExchange:    "ECDHE",
				Authentication: "ECDSA",
				Encryption:     "CHACHA20",
				EncryptionBits: 256,
				Mode:           "POLY1305",
			},
		},
		{
			name:  "DHE-RSA-AES128-GCM-SHA256",
			input: "DHE-RSA-AES128-GCM-SHA256",
			expected: CipherDecomposed{
				RawName:        "DHE-RSA-AES128-GCM-SHA256",
				KeyExchange:    "DHE",
				Authentication: "RSA",
				Encryption:     "AES",
				EncryptionBits: 128,
				Hash:           "SHA256",
				Mode:           "GCM",
			},
		},
		{
			name:  "AES256-GCM-SHA384 (RSA key exchange)",
			input: "AES256-GCM-SHA384",
			expected: CipherDecomposed{
				RawName:        "AES256-GCM-SHA384",
				Encryption:     "AES",
				EncryptionBits: 256,
				Hash:           "SHA384",
				Mode:           "GCM",
			},
		},
		{
			name:  "empty input",
			input: "",
			expected: CipherDecomposed{
				RawName: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DecomposeCipherName(tt.input)
			if result.KeyExchange != tt.expected.KeyExchange {
				t.Errorf("KeyExchange = %q, want %q", result.KeyExchange, tt.expected.KeyExchange)
			}
			if result.Authentication != tt.expected.Authentication {
				t.Errorf("Authentication = %q, want %q", result.Authentication, tt.expected.Authentication)
			}
			if result.Encryption != tt.expected.Encryption {
				t.Errorf("Encryption = %q, want %q", result.Encryption, tt.expected.Encryption)
			}
			if result.EncryptionBits != tt.expected.EncryptionBits {
				t.Errorf("EncryptionBits = %d, want %d", result.EncryptionBits, tt.expected.EncryptionBits)
			}
			if result.Hash != tt.expected.Hash {
				t.Errorf("Hash = %q, want %q", result.Hash, tt.expected.Hash)
			}
			if result.Mode != tt.expected.Mode {
				t.Errorf("Mode = %q, want %q", result.Mode, tt.expected.Mode)
			}
			if result.Protocol != tt.expected.Protocol {
				t.Errorf("Protocol = %q, want %q", result.Protocol, tt.expected.Protocol)
			}
		})
	}
}

func TestKnownIANACipher(t *testing.T) {
	tests := []struct {
		name      string
		expected  uint16
		wantFound bool
	}{
		{"TLS_AES_128_GCM_SHA256", 0x1301, true},
		{"TLS_AES_256_GCM_SHA384", 0x1302, true},
		{"ECDHE-RSA-AES256-GCM-SHA384", 0xC030, true},
		{"ECDHE-RSA-AES128-GCM-SHA256", 0xC02F, true},
		{"ECDHE-ECDSA-CHACHA20-POLY1305", 0xCCA9, true},
		{"UNKNOWN-CIPHER-NAME", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, ok := knownIANACipher(tt.name)
			if ok != tt.wantFound {
				t.Errorf("found = %v, want %v", ok, tt.wantFound)
			}
			if ok && id != tt.expected {
				t.Errorf("ID = 0x%04X, want 0x%04X", id, tt.expected)
			}
		})
	}
}

func TestIANACipherName(t *testing.T) {
	tests := []struct {
		readable string
		expected string
	}{
		{"ECDHE-RSA-AES256-GCM-SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		{"ECDHE-ECDSA-AES128-GCM-SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
		{"ECDHE-ECDSA-AES256-GCM-SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
		{"ECDHE-RSA-AES128-GCM-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		{"ECDHE-ECDSA-AES128-SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"},
		{"ECDHE-ECDSA-AES256-SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
		{"ECDHE-RSA-AES128-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},
		{"ECDHE-RSA-AES256-SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"},
		{"ECDHE-ECDSA-CHACHA20-POLY1305", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
		{"ECDHE-RSA-CHACHA20-POLY1305", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
		{"DHE-RSA-AES128-GCM-SHA256", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},
		{"DHE-RSA-AES256-GCM-SHA384", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"},
		{"DHE-RSA-AES128-SHA256", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"},
		{"DHE-RSA-AES256-SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"},
		{"AES128-GCM-SHA256", "TLS_RSA_WITH_AES_128_GCM_SHA256"},
		{"AES256-GCM-SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384"},
		{"AES128-SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA256"},
		{"AES256-SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA256"},
		// lowercase input normalised
		{"ecdhe-rsa-aes256-gcm-sha384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		{"UNKNOWN-CIPHER", "UNKNOWN-CIPHER"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.readable, func(t *testing.T) {
			result := IANACipherName(tt.readable)
			if result != tt.expected {
				t.Errorf("IANACipherName(%q) = %q, want %q", tt.readable, result, tt.expected)
			}
		})
	}
}

func TestDecomposeCipherName_LegacyAndEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected CipherDecomposed
	}{
		{
			name:  "DHE-RSA-AES256-SHA256 (CBC)",
			input: "DHE-RSA-AES256-SHA256",
			expected: CipherDecomposed{
				RawName:        "DHE-RSA-AES256-SHA256",
				KeyExchange:    "DHE",
				Authentication: "RSA",
				Encryption:     "AES",
				EncryptionBits: 256,
				Hash:           "SHA256",
			},
		},
		{
			name:  "ECDHE-RSA-AES128-SHA256 (CBC)",
			input: "ECDHE-RSA-AES128-SHA256",
			expected: CipherDecomposed{
				RawName:        "ECDHE-RSA-AES128-SHA256",
				KeyExchange:    "ECDHE",
				Authentication: "RSA",
				Encryption:     "AES",
				EncryptionBits: 128,
				Hash:           "SHA256",
			},
		},
		{
			name:  "ECDH-RSA-AES256-GCM-SHA384",
			input: "ECDH-RSA-AES256-GCM-SHA384",
			expected: CipherDecomposed{
				RawName:        "ECDH-RSA-AES256-GCM-SHA384",
				KeyExchange:    "ECDH",
				Authentication: "RSA",
				Encryption:     "AES",
				EncryptionBits: 256,
				Hash:           "SHA384",
				Mode:           "GCM",
			},
		},
		{
			name:  "DH-RSA-AES128-GCM-SHA256",
			input: "DH-RSA-AES128-GCM-SHA256",
			expected: CipherDecomposed{
				RawName:        "DH-RSA-AES128-GCM-SHA256",
				KeyExchange:    "DH",
				Authentication: "RSA",
				Encryption:     "AES",
				EncryptionBits: 128,
				Hash:           "SHA256",
				Mode:           "GCM",
			},
		},
		{
			name:  "AES128-SHA256 (RSA, no KX/Auth)",
			input: "AES128-SHA256",
			expected: CipherDecomposed{
				RawName:        "AES128-SHA256",
				Encryption:     "AES",
				EncryptionBits: 128,
				Hash:           "SHA256",
			},
		},
		{
			name:  "DES-CBC3-SHA (3DES legacy)",
			input: "DES-CBC3-SHA",
			expected: CipherDecomposed{
				RawName:        "DES-CBC3-SHA",
				Encryption:     "DES",
				EncryptionBits: 56,
				Hash:           "SHA",
			},
		},
		{
			name:  "TLS_AES_128_CCM_SHA256",
			input: "TLS_AES_128_CCM_SHA256",
			expected: CipherDecomposed{
				RawName:        "TLS_AES_128_CCM_SHA256",
				Protocol:       "TLSv1.3",
				KeyExchange:    "inline",
				Authentication: "inline",
				Encryption:     "AES",
				EncryptionBits: 128,
				Hash:           "SHA256",
				Mode:           "CCM",
			},
		},
		{
			name:  "lowercase input normalised",
			input: "ecdhe-rsa-aes256-gcm-sha384",
			expected: CipherDecomposed{
				RawName:        "ecdhe-rsa-aes256-gcm-sha384",
				KeyExchange:    "ECDHE",
				Authentication: "RSA",
				Encryption:     "AES",
				EncryptionBits: 256,
				Hash:           "SHA384",
				Mode:           "GCM",
			},
		},
		{
			name:  "ECDHE-ECDSA-AES256-SHA384 (CBC, no mode token)",
			input: "ECDHE-ECDSA-AES256-SHA384",
			expected: CipherDecomposed{
				RawName:        "ECDHE-ECDSA-AES256-SHA384",
				KeyExchange:    "ECDHE",
				Authentication: "ECDSA",
				Encryption:     "AES",
				EncryptionBits: 256,
				Hash:           "SHA384",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DecomposeCipherName(tt.input)
			if result.KeyExchange != tt.expected.KeyExchange {
				t.Errorf("KeyExchange = %q, want %q", result.KeyExchange, tt.expected.KeyExchange)
			}
			if result.Authentication != tt.expected.Authentication {
				t.Errorf("Authentication = %q, want %q", result.Authentication, tt.expected.Authentication)
			}
			if result.Encryption != tt.expected.Encryption {
				t.Errorf("Encryption = %q, want %q", result.Encryption, tt.expected.Encryption)
			}
			if result.EncryptionBits != tt.expected.EncryptionBits {
				t.Errorf("EncryptionBits = %d, want %d", result.EncryptionBits, tt.expected.EncryptionBits)
			}
			if result.Hash != tt.expected.Hash {
				t.Errorf("Hash = %q, want %q", result.Hash, tt.expected.Hash)
			}
			if result.Mode != tt.expected.Mode {
				t.Errorf("Mode = %q, want %q", result.Mode, tt.expected.Mode)
			}
			if result.Protocol != tt.expected.Protocol {
				t.Errorf("Protocol = %q, want %q", result.Protocol, tt.expected.Protocol)
			}
		})
	}
}

func TestKnownIANACipher_AllEntries(t *testing.T) {
	// Verify every entry in the knownIANACipher map round-trips correctly.
	entries := []struct {
		name string
		id   uint16
	}{
		{"TLS_AES_128_GCM_SHA256", 0x1301},
		{"TLS_AES_256_GCM_SHA384", 0x1302},
		{"TLS_CHACHA20_POLY1305_SHA256", 0x1303},
		{"TLS_AES_128_CCM_SHA256", 0x1304},
		{"TLS_AES_128_CCM_8_SHA256", 0x1305},
		{"ECDHE-ECDSA-AES128-GCM-SHA256", 0xC02B},
		{"ECDHE-ECDSA-AES256-GCM-SHA384", 0xC02C},
		{"ECDHE-RSA-AES128-GCM-SHA256", 0xC02F},
		{"ECDHE-RSA-AES256-GCM-SHA384", 0xC030},
		{"ECDHE-ECDSA-AES128-SHA256", 0xC023},
		{"ECDHE-ECDSA-AES256-SHA384", 0xC024},
		{"ECDHE-RSA-AES128-SHA256", 0xC027},
		{"ECDHE-RSA-AES256-SHA384", 0xC028},
		{"ECDHE-ECDSA-CHACHA20-POLY1305", 0xCCA9},
		{"ECDHE-RSA-CHACHA20-POLY1305", 0xCCA8},
		{"DHE-RSA-AES128-GCM-SHA256", 0x009E},
		{"DHE-RSA-AES256-GCM-SHA384", 0x009F},
		{"DHE-RSA-AES128-SHA256", 0x0067},
		{"DHE-RSA-AES256-SHA256", 0x006B},
		{"AES128-GCM-SHA256", 0x009C},
		{"AES256-GCM-SHA384", 0x009D},
		{"AES128-SHA256", 0x003C},
		{"AES256-SHA256", 0x003D},
	}
	for _, e := range entries {
		t.Run(e.name, func(t *testing.T) {
			id, ok := knownIANACipher(e.name)
			if !ok {
				t.Fatalf("expected to find %q in knownIANACipher", e.name)
			}
			if id != e.id {
				t.Errorf("ID = 0x%04X, want 0x%04X", id, e.id)
			}
			// Case-insensitive lookup
			lower := strings.ToLower(e.name)
			idLower, okLower := knownIANACipher(lower)
			if !okLower {
				t.Errorf("lowercase lookup failed for %q", lower)
			} else if idLower != e.id {
				t.Errorf("lowercase ID = 0x%04X, want 0x%04X", idLower, e.id)
			}
		})
	}
}

func TestIsHash(t *testing.T) {
	positives := []string{"SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "MD5", "SHA",
		"sha256", "Sha384"}
	for _, h := range positives {
		if !isHash(h) {
			t.Errorf("isHash(%q) = false, want true", h)
		}
	}
	negatives := []string{"AES", "GCM", "RSA", "ECDHE", "POLY1305", ""}
	for _, h := range negatives {
		if isHash(h) {
			t.Errorf("isHash(%q) = true, want false", h)
		}
	}
}

func TestExtractBits(t *testing.T) {
	cases := []struct {
		s    string
		want int
	}{
		{"AES128", 128},
		{"AES256", 256},
		{"AES192", 192},
		{"CAMELLIA256", 256},
		{"RC240", 40},
		{"DES56", 56},
		{"3DES112", 112},
		{"SHA384", 384},
		{"AES512", 512},
		{"UNKNOWN", 0},
	}
	for _, c := range cases {
		got := extractBits(c.s)
		if got != c.want {
			t.Errorf("extractBits(%q) = %d, want %d", c.s, got, c.want)
		}
	}
}

func TestDefaultBitsForAlgo(t *testing.T) {
	cases := []struct {
		algo string
		want int
	}{
		{"CHACHA20", 256},
		{"AES", 128},
		{"CAMELLIA", 128},
		{"ARIA", 128},
		{"SEED", 128},
		{"DES", 56},
		{"3DES", 112},
		{"IDEA", 128},
		{"RC2", 40},
		{"RC4", 128},
		{"UNKNOWN", 0},
	}
	for _, c := range cases {
		got := defaultBitsForAlgo(c.algo)
		if got != c.want {
			t.Errorf("defaultBitsForAlgo(%q) = %d, want %d", c.algo, got, c.want)
		}
	}
}

func TestIsDigits(t *testing.T) {
	trues := []string{"0", "128", "256"}
	for _, s := range trues {
		if !isDigits(s) {
			t.Errorf("isDigits(%q) should be true", s)
		}
	}
	falses := []string{"", "abc", "12a", "1.0"}
	for _, s := range falses {
		if isDigits(s) {
			t.Errorf("isDigits(%q) should be false", s)
		}
	}
}
