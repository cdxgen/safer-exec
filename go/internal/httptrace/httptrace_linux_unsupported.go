//go:build linux && !(amd64 || arm64)

// Stub for Linux architectures without a pre-compiled BPF object (e.g. 386, mips).
package httptrace

// New returns ErrUnsupported on Linux architectures other than amd64/arm64.
func New() (Tracer, error) {
	return nil, ErrUnsupported
}

// PidDescendants is a no-op on unsupported arches.
func PidDescendants(_ uint32) map[uint32]struct{} {
	return nil
}
