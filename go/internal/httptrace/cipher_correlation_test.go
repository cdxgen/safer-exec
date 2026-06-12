//go:build linux && (amd64 || arm64)

package httptrace

import (
	"encoding/binary"
	"testing"
)

// newTestTracer returns a minimal linuxTracer with cipher maps initialised,
// suitable for unit-testing readCipherLoop correlation logic without loading BPF.
func newTestTracer() *linuxTracer {
	return &linuxTracer{
		cipherMap:       make(map[uint64]CipherResult),
		cipherNameMap:   make(map[uint32]string),
		cipherPtrToConn: make(map[uint32]uint64),
	}
}

// makeCipherEventRaw encodes a cipher event into the on-wire byte slice,
// matching the actual C struct layout including implicit alignment padding.
// Layout: PID(4)+Source(4)+Pad(4)+[align4]+ConnID(8)+Bits(4)+Name(128) = 160 bytes
func makeCipherEventRaw(pid uint32, source uint32, connID uint64, bits uint32, name string) []byte {
	const size = 4 + 4 + 4 + 4 + 8 + 4 + maxCipherName // = 160 bytes
	buf := make([]byte, size)
	binary.LittleEndian.PutUint32(buf[0:4], pid)
	binary.LittleEndian.PutUint32(buf[4:8], source)
	// buf[8:12]  = explicit pad field (zero)
	// buf[12:16] = implicit alignment padding (zero)
	binary.LittleEndian.PutUint64(buf[16:24], connID)
	binary.LittleEndian.PutUint32(buf[24:28], bits)
	copy(buf[28:], name)
	return buf
}

// simulateCipherEvent feeds a raw byte slice through decodeCipherEvent and then
// applies the same branch logic used in readCipherLoop, operating directly on
// the tracer's maps (no goroutine / ring buffer needed).
func (t *linuxTracer) simulateCipherEvent(raw []byte) {
	ev := decodeCipherEvent(raw)
	if ev == nil {
		return
	}
	name := ""
	for i, b := range ev.Name {
		if b == 0 {
			name = string(ev.Name[:i])
			break
		}
	}
	if name == "" {
		// check if whole array is non-zero (shouldn't happen, but be safe)
		for _, b := range ev.Name {
			if b != 0 {
				name = string(ev.Name[:])
				break
			}
		}
	}

	t.cipherMu.Lock()
	defer t.cipherMu.Unlock()

	if ev.Bits > 0 && name == "" && ev.ConnID > 0xFFFFFFFF {
		// SSL_get_current_cipher: connID = ssl*, bits = lower32(cipher*)
		cipherPtr := uint32(ev.Bits)
		t.cipherPtrToConn[cipherPtr] = ev.ConnID
		if cipherName, ok := t.cipherNameMap[cipherPtr]; ok {
			cr := t.cipherMap[ev.ConnID]
			cr.ConnID = ev.ConnID
			cr.PID = ev.PID
			cr.Name = cipherName
			cr.IANAName = IANACipherName(cipherName)
			cr.IANAID, _ = knownIANACipher(cipherName)
			t.cipherMap[ev.ConnID] = cr
			t.cipherMap[uint64(ev.PID)] = cr
		} else {
			t.cipherMap[ev.ConnID] = CipherResult{ConnID: ev.ConnID, PID: ev.PID}
		}
	} else if ev.Bits > 0 && name == "" && ev.ConnID < 0x100000000 {
		// SSL_CIPHER_get_bits: connID lower32 = cipher*, bits = secret bits
		cipherPtr := uint32(ev.ConnID)
		if sslConn, ok := t.cipherPtrToConn[cipherPtr]; ok {
			if cr, ok := t.cipherMap[sslConn]; ok {
				cr.Bits = int(ev.Bits)
				t.cipherMap[sslConn] = cr
				t.cipherMap[uint64(ev.PID)] = cr
			}
		}
	} else if name != "" && ev.Bits == 0 && ev.ConnID > 0xFFFFFFFF {
		// SSL_get_version: connID = ssl*, name = version string
		if existing, ok := t.cipherMap[ev.ConnID]; ok {
			existing.Protocol = name
			t.cipherMap[ev.ConnID] = existing
			t.cipherMap[uint64(ev.PID)] = existing
		}
	} else if name != "" && ev.ConnID < 0x100000000 {
		// SSL_CIPHER_get_name: connID lower32 = cipher*, name = cipher suite string
		cipherPtr := uint32(ev.ConnID)
		t.cipherNameMap[cipherPtr] = name
		if sslConn, ok := t.cipherPtrToConn[cipherPtr]; ok {
			cr := t.cipherMap[sslConn]
			cr.ConnID = sslConn
			cr.Name = name
			cr.IANAName = IANACipherName(name)
			cr.IANAID, _ = knownIANACipher(name)
			t.cipherMap[sslConn] = cr
			t.cipherMap[uint64(ev.PID)] = cr
		}
	}
}

const (
	testSSLPtr    uint64 = 0xABCD_0000_1234_5678 // realistic 64-bit ssl* pointer
	testCipherPtr uint32 = 0xDEAD_BEEF           // realistic 32-bit cipher* pointer
	testPID       uint32 = 9999
)

// TestCipherCorrelation_InOrder verifies the normal case: SSL_get_current_cipher
// fires first (establishing ssl* → cipher* mapping), then SSL_CIPHER_get_name.
func TestCipherCorrelation_InOrder(t *testing.T) {
	tr := newTestTracer()

	// 1. SSL_get_current_cipher uretprobe: conn_id=ssl*, bits=cipher*
	tr.simulateCipherEvent(makeCipherEventRaw(testPID, 0, testSSLPtr, testCipherPtr, ""))

	// 2. SSL_CIPHER_get_name uretprobe: conn_id=lower32(cipher*), name=cipher_name
	tr.simulateCipherEvent(makeCipherEventRaw(testPID, 0, uint64(testCipherPtr), 0, "ECDHE-RSA-AES256-GCM-SHA384"))

	cr, ok := tr.CipherForConnID(testSSLPtr, testPID)
	if !ok {
		t.Fatal("CipherForConnID: not found")
	}
	if cr.Name != "ECDHE-RSA-AES256-GCM-SHA384" {
		t.Errorf("Name = %q, want ECDHE-RSA-AES256-GCM-SHA384", cr.Name)
	}
	if cr.IANAID != 0xC030 {
		t.Errorf("IANAID = 0x%04X, want 0xC030", cr.IANAID)
	}
}

// TestCipherCorrelation_OutOfOrder verifies that SSL_CIPHER_get_name arriving
// before SSL_get_current_cipher is handled correctly via cipherNameMap.
func TestCipherCorrelation_OutOfOrder(t *testing.T) {
	tr := newTestTracer()

	// 1. SSL_CIPHER_get_name arrives first
	tr.simulateCipherEvent(makeCipherEventRaw(testPID, 0, uint64(testCipherPtr), 0, "ECDHE-RSA-AES256-GCM-SHA384"))

	// Before SSL_get_current_cipher fires there is no ssl* → result yet.
	_, ok := tr.CipherForConnID(testSSLPtr, testPID)
	// May be found via PID fallback — that's also acceptable; what matters is
	// the final state after SSL_get_current_cipher fires.
	_ = ok

	// 2. SSL_get_current_cipher fires — should pick up the already-stored name.
	tr.simulateCipherEvent(makeCipherEventRaw(testPID, 0, testSSLPtr, testCipherPtr, ""))

	cr, ok := tr.CipherForConnID(testSSLPtr, testPID)
	if !ok {
		t.Fatal("CipherForConnID: not found after out-of-order events")
	}
	if cr.Name != "ECDHE-RSA-AES256-GCM-SHA384" {
		t.Errorf("Name = %q, want ECDHE-RSA-AES256-GCM-SHA384", cr.Name)
	}
}

// TestCipherCorrelation_WithBits verifies that SSL_CIPHER_get_bits is correlated
// to the correct connection.
func TestCipherCorrelation_WithBits(t *testing.T) {
	tr := newTestTracer()

	tr.simulateCipherEvent(makeCipherEventRaw(testPID, 0, testSSLPtr, testCipherPtr, ""))
	tr.simulateCipherEvent(makeCipherEventRaw(testPID, 0, uint64(testCipherPtr), 0, "ECDHE-RSA-AES256-GCM-SHA384"))
	// SSL_CIPHER_get_bits: conn_id=lower32(cipher*), bits=256
	tr.simulateCipherEvent(makeCipherEventRaw(testPID, 0, uint64(testCipherPtr), 256, ""))

	cr, ok := tr.CipherForConnID(testSSLPtr, testPID)
	if !ok {
		t.Fatal("CipherForConnID: not found")
	}
	if cr.Bits != 256 {
		t.Errorf("Bits = %d, want 256", cr.Bits)
	}
}

// TestCipherCorrelation_TLSVersion verifies that SSL_get_version updates the
// protocol field on the connection's CipherResult.
func TestCipherCorrelation_TLSVersion(t *testing.T) {
	tr := newTestTracer()

	tr.simulateCipherEvent(makeCipherEventRaw(testPID, 0, testSSLPtr, testCipherPtr, ""))
	tr.simulateCipherEvent(makeCipherEventRaw(testPID, 0, uint64(testCipherPtr), 0, "TLS_AES_256_GCM_SHA384"))
	// SSL_get_version: conn_id=ssl*, name=version
	tr.simulateCipherEvent(makeCipherEventRaw(testPID, 0, testSSLPtr, 0, "TLSv1.3"))

	cr, ok := tr.CipherForConnID(testSSLPtr, testPID)
	if !ok {
		t.Fatal("CipherForConnID: not found")
	}
	if cr.Protocol != "TLSv1.3" {
		t.Errorf("Protocol = %q, want TLSv1.3", cr.Protocol)
	}
}

// TestCipherCorrelation_MultipleConnections verifies that two concurrent
// connections with different ssl* pointers are tracked independently.
func TestCipherCorrelation_MultipleConnections(t *testing.T) {
	tr := newTestTracer()

	const (
		sslA    uint64 = 0x1111_0000_AAAA_0001
		sslB    uint64 = 0x2222_0000_BBBB_0002
		cipherA uint32 = 0x1111_AAAA
		cipherB uint32 = 0x2222_BBBB
	)

	// Connection A
	tr.simulateCipherEvent(makeCipherEventRaw(testPID, 0, sslA, cipherA, ""))
	tr.simulateCipherEvent(makeCipherEventRaw(testPID, 0, uint64(cipherA), 0, "ECDHE-RSA-AES256-GCM-SHA384"))

	// Connection B
	tr.simulateCipherEvent(makeCipherEventRaw(testPID, 0, sslB, cipherB, ""))
	tr.simulateCipherEvent(makeCipherEventRaw(testPID, 0, uint64(cipherB), 0, "ECDHE-ECDSA-AES128-GCM-SHA256"))

	crA, okA := tr.CipherForConnID(sslA, testPID)
	crB, okB := tr.CipherForConnID(sslB, testPID)

	if !okA {
		t.Fatal("connection A not found")
	}
	if !okB {
		t.Fatal("connection B not found")
	}
	if crA.Name != "ECDHE-RSA-AES256-GCM-SHA384" {
		t.Errorf("A.Name = %q, want ECDHE-RSA-AES256-GCM-SHA384", crA.Name)
	}
	if crB.Name != "ECDHE-ECDSA-AES128-GCM-SHA256" {
		t.Errorf("B.Name = %q, want ECDHE-ECDSA-AES128-GCM-SHA256", crB.Name)
	}
}
