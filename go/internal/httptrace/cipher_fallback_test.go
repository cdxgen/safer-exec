package httptrace

import (
	"encoding/binary"
	"testing"
)

func TestCipherNameByID(t *testing.T) {
	name, ok := CipherNameByID(0x1301)
	if !ok || name != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("expected TLS_AES_128_GCM_SHA256, got %q (ok=%v)", name, ok)
	}
	name, ok = CipherNameByID(0xC02F)
	if !ok || name != "ECDHE-RSA-AES128-GCM-SHA256" {
		t.Errorf("expected ECDHE-RSA-AES128-GCM-SHA256, got %q (ok=%v)", name, ok)
	}
	_, ok = CipherNameByID(0x0000)
	if ok {
		t.Error("expected ok=false for unknown ID")
	}
}

func TestParseServerHelloFallback(t *testing.T) {
	// Let's build a mock ServerHello handshake packet:
	// 5 bytes TLS record header: 0x16, 0x03, 0x03, 0x00, 0x50
	// 4 bytes Handshake header: 0x02, 0x00, 0x00, 0x4c (ServerHello, length 76)
	// 2 bytes Version: 0x03, 0x03 (TLS 1.2)
	// 32 bytes Random
	// 1 byte Session ID Length: 0x20 (32 bytes)
	// 32 bytes Session ID
	// 2 bytes Cipher Suite: 0xC0, 0x2F (ECDHE-RSA-AES128-GCM-SHA256)
	// 1 byte Compression Method: 0x00
	sessionIDLen := 32
	payloadLen := 5 + 4 + 2 + 32 + 1 + sessionIDLen + 2 + 1
	payload := make([]byte, payloadLen)

	payload[0] = 0x16 // Handshake
	payload[1] = 0x03 // TLS 1.x
	payload[2] = 0x03 // TLS 1.2
	binary.BigEndian.PutUint16(payload[3:5], uint16(payloadLen-5))

	payload[5] = 0x02 // ServerHello
	// handshake length
	payload[6] = 0x00
	binary.BigEndian.PutUint16(payload[7:9], uint16(payloadLen-9))

	payload[9] = 0x03 // Version TLS 1.2
	payload[10] = 0x03

	// Session ID Length
	payload[43] = byte(sessionIDLen)

	// Cipher Suite at 44 + sessionIDLen
	binary.BigEndian.PutUint16(payload[44+sessionIDLen:46+sessionIDLen], 0xC02F)

	// Test parsing matching readCipherLoop's fallback logic
	if payload[0] == 0x16 && payload[1] == 0x03 {
		hsType := payload[5]
		if hsType == 0x02 {
			sIDLen := int(payload[43])
			if 44+sIDLen+2 <= len(payload) {
				cipherID := binary.BigEndian.Uint16(payload[44+sIDLen : 46+sIDLen])
				name, ok := CipherNameByID(cipherID)
				if !ok || name != "ECDHE-RSA-AES128-GCM-SHA256" {
					t.Fatalf("failed to parse cipher suite name: got %q (ok=%v)", name, ok)
				}
			} else {
				t.Fatal("payload too short for session ID and cipher suite")
			}
		} else {
			t.Fatal("expected ServerHello handshake type")
		}
	} else {
		t.Fatal("expected TLS handshake record header")
	}
}
