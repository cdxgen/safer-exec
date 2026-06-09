//go:build linux && (amd64 || arm64)

package httptrace

import (
	"encoding/binary"
	"testing"
)

// TestDecodeEvent verifies that decodeEvent correctly parses the wire layout
// produced by the BPF program:
//
//	PID(4) + Len(4) + Source(1) + Pad(7) + ConnID(8) + Buf(maxBufSize)
func TestDecodeEvent(t *testing.T) {
	const headerSize = 4 + 4 + 1 + 7 + 8 // = 24
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	raw := make([]byte, headerSize+maxBufSize)

	binary.LittleEndian.PutUint32(raw[0:4], 1234)                 // PID
	binary.LittleEndian.PutUint32(raw[4:8], uint32(len(payload))) // Len
	raw[8] = 0                                                    // Source = SourceSSLWrite
	// pad[9:16] already zero
	binary.LittleEndian.PutUint64(raw[16:24], 0xdeadbeefcafe) // ConnID
	copy(raw[24:], payload)

	ev := decodeEvent(raw)
	if ev == nil {
		t.Fatal("decodeEvent returned nil")
	}
	if ev.PID != 1234 {
		t.Errorf("PID=%d want 1234", ev.PID)
	}
	if ev.ConnID != 0xdeadbeefcafe {
		t.Errorf("ConnID=0x%x want 0xdeadbeefcafe", ev.ConnID)
	}
	if ev.Len != uint32(len(payload)) {
		t.Errorf("Len=%d want %d", ev.Len, len(payload))
	}
	if string(ev.Buf[:ev.Len]) != string(payload) {
		t.Errorf("Buf mismatch: got %q want %q", ev.Buf[:ev.Len], payload)
	}
}

// TestDecodeEvent_TooShort confirms decodeEvent rejects truncated headers.
func TestDecodeEvent_TooShort(t *testing.T) {
	if ev := decodeEvent([]byte{0x01, 0x02}); ev != nil {
		t.Error("expected nil for too-short input")
	}
}

// TestDecodeEvent_LenCap confirms that an oversized Len field is capped at maxBufSize.
func TestDecodeEvent_LenCap(t *testing.T) {
	const headerSize = 4 + 4 + 1 + 7 + 8 // = 24
	raw := make([]byte, headerSize+maxBufSize)
	binary.LittleEndian.PutUint32(raw[4:8], maxBufSize+9999) // Len > maxBufSize
	ev := decodeEvent(raw)
	if ev == nil {
		t.Fatal("expected non-nil event")
	}
	if ev.Len > maxBufSize {
		t.Errorf("Len=%d exceeds maxBufSize=%d", ev.Len, maxBufSize)
	}
}
