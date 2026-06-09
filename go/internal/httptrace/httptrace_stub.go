//go:build !linux

package httptrace

// New returns ErrUnsupported on non-Linux platforms. All eBPF functionality
// requires Linux with kernel >= 5.8 and CAP_BPF + CAP_PERFMON.
func New() (Tracer, error) {
	return nil, ErrUnsupported
}

// PidDescendants is a no-op on non-Linux platforms.
func PidDescendants(_ uint32) map[uint32]struct{} {
	return nil
}
