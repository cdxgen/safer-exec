package mxc

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
)

// wxc-exec shares its stderr handle with the workload, and after the workload
// exits it writes two kinds of machine-readable lines there:
//
//   - an error envelope, {"error":{"code":"policy_validation"|"backend_error",
//     "message":...,"extended_error":...}}, whenever MXC itself failed (the
//     process exit code is then 1 or -1);
//   - a capture pointer, {"type":"captureDenials","outputPath":...}, naming
//     the denial report it wrote.
//
// The envelope can follow unterminated diagnostic text on the same line, so
// StderrFilter matches the markers anywhere in the stream, forwards every
// other byte unchanged and as soon as it arrives, and consumes the protocol
// lines. Only a tail that could still become a marker is held back.
//
// Because the workload writes to the same handle, everything here is
// untrusted: a workload can print lines that look exactly like MXC's. The
// filter therefore only reports what it saw, and the engine treats it as a
// hint. Capture pointers are consumed but never surfaced; the engine finds
// the report in its own run directory instead of following a path the
// workload could have chosen.

var (
	envelopeMarker = []byte(`{"error":{"code":"`)
	pointerMarker  = []byte(`{"type":"captureDenials"`)
)

// maxMarkerLine bounds how much a suspected protocol line may buffer before
// it is treated as ordinary output.
const maxMarkerLine = 1 << 20

// Envelope is MXC's structured infrastructure error.
type Envelope struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	ExtendedError string `json:"extended_error,omitempty"`
}

// Envelope codes MXC emits; anything else is not an MXC envelope.
const (
	CodePolicyValidation = "policy_validation"
	CodeBackendError     = "backend_error"
)

// IsTimeout reports whether the envelope is MXC's process-timeout result.
func (e *Envelope) IsTimeout() bool {
	return e != nil && e.Code == CodeBackendError && strings.HasPrefix(e.Message, "script timed out")
}

// StderrFilter is an io.Writer that forwards to an underlying writer while
// extracting MXC protocol lines. It is safe for concurrent use.
type StderrFilter struct {
	mu       sync.Mutex
	w        io.Writer
	pending  []byte
	inMarker bool
	lastByte byte
	wrote    bool
	envelope *Envelope
}

// NewStderrFilter returns a filter forwarding to w.
func NewStderrFilter(w io.Writer) *StderrFilter {
	return &StderrFilter{w: w}
}

// Write implements io.Writer. It always reports len(p) consumed; forwarding
// errors on the underlying writer are ignored so a closed terminal cannot
// stall the workload.
func (f *StderrFilter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	buf := append(f.pending, p...)
	f.pending = nil
	for len(buf) > 0 {
		if f.inMarker {
			nl := bytes.IndexByte(buf, '\n')
			if nl < 0 {
				if len(buf) > maxMarkerLine {
					f.forward(buf)
					f.inMarker = false
					buf = nil
					break
				}
				f.pending = append([]byte(nil), buf...)
				return len(p), nil
			}
			f.consumeLine(buf[:nl], true)
			buf = buf[nl+1:]
			f.inMarker = false
			continue
		}
		i := indexMarker(buf)
		if i >= 0 {
			f.forward(buf[:i])
			buf = buf[i:]
			f.inMarker = true
			continue
		}
		k := markerPrefixSuffix(buf)
		f.forward(buf[:len(buf)-k])
		if k > 0 {
			f.pending = append([]byte(nil), buf[len(buf)-k:]...)
		}
		break
	}
	return len(p), nil
}

// Close flushes any held-back bytes. A protocol line still open at EOF is
// interpreted without its terminating newline.
func (f *StderrFilter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pending) > 0 {
		if f.inMarker {
			f.consumeLine(f.pending, false)
		} else {
			f.forward(f.pending)
		}
	}
	f.pending = nil
	f.inMarker = false
	return nil
}

// Emit writes a complete line produced by the engine itself (an audit entry)
// without interleaving it into a partially forwarded workload line: if the
// last forwarded byte did not end a line, a newline is written first.
func (f *StderrFilter) Emit(line []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.terminateLine()
	f.forward(line)
}

// EnsureNewline terminates a partially forwarded line, so that output the
// engine writes directly to stderr afterwards starts on a fresh line.
func (f *StderrFilter) EnsureNewline() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.terminateLine()
}

// Envelope returns the last MXC error envelope seen on stderr, if any. MXC
// writes its envelope after the workload has exited, so the last one is the
// genuine one when both are present; the workload can still print one of its
// own, so callers must corroborate it (see the engine).
func (f *StderrFilter) Envelope() *Envelope {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.envelope
}

func (f *StderrFilter) forward(b []byte) {
	if len(b) == 0 {
		return
	}
	_, _ = f.w.Write(b)
	f.lastByte = b[len(b)-1]
	f.wrote = true
}

// consumeLine interprets a suspected protocol line. Anything that is not a
// well-formed MXC protocol object is forwarded verbatim.
//
// A workload can leave a marker unterminated so that MXC's genuine line is
// glued onto it and no longer parses. MXC's line always ends the glued line,
// so when the whole line does not parse, the last marker inside it is tried
// on its own and the text before it is forwarded as ordinary output.
func (f *StderrFilter) consumeLine(line []byte, hadNewline bool) {
	trimmed := bytes.TrimRight(line, "\r")
	if f.consumeProtocol(trimmed) {
		return
	}
	if i := protocolSuffix(trimmed); i > 0 {
		f.forward(trimmed[:i])
		f.consumeProtocol(trimmed[i:])
		return
	}
	f.forward(line)
	if hadNewline {
		f.forward([]byte{'\n'})
	}
}

// consumeProtocol records b if it is a well-formed protocol object.
func (f *StderrFilter) consumeProtocol(b []byte) bool {
	env, ok := parseProtocol(b)
	if !ok {
		return false
	}
	if env != nil {
		f.envelope = env
	}
	f.terminateLine()
	return true
}

// parseProtocol parses one protocol object: an envelope with one of MXC's
// codes (returned), or a capture pointer (recognized, then dropped).
func parseProtocol(b []byte) (*Envelope, bool) {
	switch {
	case bytes.HasPrefix(b, envelopeMarker):
		var env struct {
			Error *Envelope `json:"error"`
		}
		if json.Unmarshal(b, &env) == nil && env.Error != nil &&
			(env.Error.Code == CodePolicyValidation || env.Error.Code == CodeBackendError) {
			return env.Error, true
		}
	case bytes.HasPrefix(b, pointerMarker):
		var cp struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(b, &cp) == nil && cp.Type == "captureDenials" {
			return nil, true
		}
	}
	return nil, false
}

// terminateLine ends a line of forwarded text that a consumed protocol
// object interrupted, so later diagnostics start on a fresh line.
func (f *StderrFilter) terminateLine() {
	if f.wrote && f.lastByte != '\n' {
		f.forward([]byte{'\n'})
	}
}

// protocolSuffix returns the earliest index after the start of b at which a
// marker begins a well-formed protocol object running to the end of b, or -1.
// Scanning from the front lets a marker quoted inside MXC's own message text
// stay part of that message.
func protocolSuffix(b []byte) int {
	for i := 1; i < len(b); {
		j := indexMarker(b[i:])
		if j < 0 {
			return -1
		}
		i += j
		if _, ok := parseProtocol(b[i:]); ok {
			return i
		}
		i++
	}
	return -1
}

func indexMarker(b []byte) int {
	i := bytes.Index(b, envelopeMarker)
	j := bytes.Index(b, pointerMarker)
	switch {
	case i < 0:
		return j
	case j < 0:
		return i
	case i < j:
		return i
	default:
		return j
	}
}

// markerPrefixSuffix returns the length of the longest suffix of b that is a
// proper prefix of a marker.
func markerPrefixSuffix(b []byte) int {
	best := 0
	for _, m := range [][]byte{envelopeMarker, pointerMarker} {
		maxK := min(len(m)-1, len(b))
		for k := maxK; k > best; k-- {
			if bytes.Equal(b[len(b)-k:], m[:k]) {
				best = k
				break
			}
		}
	}
	return best
}
