package mxc

import (
	"bytes"
	"strings"
	"testing"
)

const (
	testEnvelope = `{"error":{"code":"backend_error","message":"CreateProcessW failed with error code 2 (0x00000002).","extended_error":"WIN32_ERROR(2)"}}`
	testPointer  = `{"type":"captureDenials","outputPath":"C:\\run\\denials.42_ab.json","exitCode":1,"totalDenials":3,"deniedResourcesTruncated":false}`
)

func feed(chunks ...string) (*StderrFilter, *bytes.Buffer) {
	var out bytes.Buffer
	f := NewStderrFilter(&out)
	for _, c := range chunks {
		n, err := f.Write([]byte(c))
		if err != nil || n != len(c) {
			panic("short write")
		}
	}
	_ = f.Close()
	return f, &out
}

func TestStderrFilterPassThrough(t *testing.T) {
	in := "plain output\n{\"json\":\"from the workload\"}\npartial {\"err"
	f, out := feed(in)
	if out.String() != in {
		t.Errorf("output altered: %q", out.String())
	}
	if f.Envelope() != nil || f.CapturePointer() != nil {
		t.Error("spurious protocol objects")
	}
}

func TestStderrFilterEnvelopeMidLine(t *testing.T) {
	f, out := feed("workload line\nCreateProcessW failed with error code 2 (0x00000002)." + testEnvelope + "\n")
	env := f.Envelope()
	if env == nil || env.Code != "backend_error" || env.ExtendedError != "WIN32_ERROR(2)" {
		t.Fatalf("envelope = %+v", env)
	}
	if want := "workload line\nCreateProcessW failed with error code 2 (0x00000002).\n"; out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

func TestStderrFilterPointerAndSplitWrites(t *testing.T) {
	stream := "before\n" + testPointer + "\nafter\n"
	// Every split point, including inside the marker prefix.
	for i := 0; i <= len(stream); i++ {
		f, out := feed(stream[:i], stream[i:])
		if out.String() != "before\nafter\n" {
			t.Fatalf("split %d: output %q", i, out.String())
		}
		p := f.CapturePointer()
		if p == nil || p.OutputPath != `C:\run\denials.42_ab.json` || p.TotalDenials != 3 || p.ExitCode != 1 {
			t.Fatalf("split %d: pointer %+v", i, p)
		}
	}
	// Byte-at-a-time delivery.
	var chunks []string
	for _, b := range []byte(stream) {
		chunks = append(chunks, string(b))
	}
	if f, out := feed(chunks...); out.String() != "before\nafter\n" || f.CapturePointer() == nil {
		t.Errorf("byte-wise: %q", out.String())
	}
}

func TestStderrFilterMalformedMarkerIsForwarded(t *testing.T) {
	in := `{"error":{"code":"not json` + "\n" + `{"type":"captureDenials" is just text` + "\n"
	f, out := feed(in)
	if out.String() != in {
		t.Errorf("output = %q", out.String())
	}
	if f.Envelope() != nil || f.CapturePointer() != nil {
		t.Error("malformed marker interpreted")
	}
}

func TestStderrFilterEnvelopeAtEOFWithoutNewline(t *testing.T) {
	f, out := feed("x\n", testEnvelope)
	if f.Envelope() == nil || out.String() != "x\n" {
		t.Errorf("envelope at EOF: %+v %q", f.Envelope(), out.String())
	}
}

func TestStderrFilterHeldPrefixFlushedOnClose(t *testing.T) {
	_, out := feed(`progress {"er`)
	if out.String() != `progress {"er` {
		t.Errorf("held prefix lost: %q", out.String())
	}
}

func TestStderrFilterOversizedMarkerLine(t *testing.T) {
	big := `{"error":{"code":"` + strings.Repeat("x", maxMarkerLine+10)
	f, out := feed(big, "\nnext\n")
	if f.Envelope() != nil || !strings.HasPrefix(out.String(), `{"error"`) || !strings.HasSuffix(out.String(), "next\n") {
		t.Errorf("oversized marker line mishandled (len %d)", out.Len())
	}
}

func TestStderrFilterEmitStartsFreshLine(t *testing.T) {
	var out bytes.Buffer
	f := NewStderrFilter(&out)
	_, _ = f.Write([]byte("partial"))
	f.Emit([]byte(`{"type":"process-exec"}` + "\n"))
	_, _ = f.Write([]byte("rest\n"))
	f.EnsureNewline() // already at a line start: no-op
	_ = f.Close()
	if want := "partial\n" + `{"type":"process-exec"}` + "\nrest\n"; out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

func TestEnvelopeIsTimeout(t *testing.T) {
	if !(&Envelope{Code: "backend_error", Message: "script timed out after 2500ms"}).IsTimeout() {
		t.Error("timeout not recognised")
	}
	if (&Envelope{Code: "policy_validation", Message: "script timed out"}).IsTimeout() {
		t.Error("policy error treated as timeout")
	}
	var nilEnv *Envelope
	if nilEnv.IsTimeout() {
		t.Error("nil envelope treated as timeout")
	}
}
