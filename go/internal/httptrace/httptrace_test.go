package httptrace_test

import (
	"errors"
	"testing"

	"github.com/cdxgen/safer-exec/go/internal/httptrace"
)

// TestNew_Unsupported verifies that New() returns ErrUnsupported gracefully
// when eBPF is not available (non-Linux, missing caps, kernel too old).
// On Linux/amd64 or Linux/arm64 with full capabilities this test is skipped.
func TestNew_Unsupported(t *testing.T) {
	tr, err := httptrace.New()
	if err == nil {
		// eBPF is available — verify the tracer has a functional Events channel.
		defer tr.Close()
		if tr.Events() == nil {
			t.Error("Events() channel is nil on a live tracer")
		}
		t.Skip("eBPF available — skipping ErrUnsupported check")
	}
	if !errors.Is(err, httptrace.ErrUnsupported) {
		t.Errorf("New() error = %v, want wrapping ErrUnsupported", err)
	}
	if tr != nil {
		t.Error("New() should return nil Tracer on error")
	}
}

// TestPidDescendants verifies that PidDescendants includes the root PID and
// does not panic on an unknown PID.
func TestPidDescendants(t *testing.T) {
	// Unknown PID — should return just the seed (or empty map on non-Linux).
	result := httptrace.PidDescendants(999999)
	// On Linux we expect the seed PID in the result even if it doesn't exist.
	// On other platforms the function returns nil.
	if result != nil {
		if _, ok := result[999999]; !ok {
			t.Error("PidDescendants should include the root PID")
		}
	}
}
