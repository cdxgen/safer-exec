package httptrace

import (
	"bytes"
	"encoding/binary"
)

// httpMethods is the set of valid HTTP/1.x method tokens (RFC 7230 §3.1.1).
var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("PATCH "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("CONNECT "),
	[]byte("TRACE "),
}

// ParseHTTPRequest attempts to parse an HTTP/1.x request from raw bytes
// captured from a TLS write buffer. Returns (method, path, host, true) on
// success or ("", "", "", false) when the buffer doesn't look like HTTP/1.x.
//
// Only the first request line and the Host header are extracted; the body
// and subsequent pipelined requests are ignored.
func ParseHTTPRequest(data []byte) (method, path, host string, ok bool) {
	if len(data) < 14 { // "GET / HTTP/1.1" is 14 bytes
		return
	}

	// Detect HTTP method at start of buffer.
	var mBytes []byte
	for _, m := range httpMethods {
		if bytes.HasPrefix(data, m) {
			mBytes = m
			break
		}
	}
	if mBytes == nil {
		return
	}
	method = string(bytes.TrimSuffix(mBytes, []byte(" ")))

	// Find the first CRLF (end of request line).
	lineEnd := bytes.IndexByte(data, '\n')
	if lineEnd < 0 {
		lineEnd = len(data)
	}
	requestLine := data[:lineEnd]
	if len(requestLine) > 0 && requestLine[len(requestLine)-1] == '\r' {
		requestLine = requestLine[:len(requestLine)-1]
	}

	// Extract path: between the method prefix and the trailing " HTTP/1.x".
	rest := requestLine[len(mBytes):]
	if httpIdx := bytes.LastIndex(rest, []byte(" HTTP/")); httpIdx >= 0 {
		path = string(rest[:httpIdx])
	} else {
		path = string(rest)
	}
	if path == "" {
		path = "/"
	}

	// Scan headers for "Host:".
	headers := data[lineEnd+1:]
	host = extractHeader(headers, "Host")

	ok = true
	return
}

// http2Preface is the fixed 24-byte client connection preface for HTTP/2 (RFC 7540 §3.5).
var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// http2FrameTypes maps known HTTP/2 frame type bytes to true (RFC 7540 §6).
var http2FrameTypes = map[byte]bool{
	0: true, // DATA
	1: true, // HEADERS
	2: true, // PRIORITY
	3: true, // RST_STREAM
	4: true, // SETTINGS
	5: true, // PUSH_PROMISE
	6: true, // PING
	7: true, // GOAWAY
	8: true, // WINDOW_UPDATE
	9: true, // CONTINUATION
}

// IsHTTP2 returns true when data appears to be HTTP/2 traffic.
// It recognises both the explicit connection preface ("PRI * HTTP/2.0…")
// and bare binary frame headers (3-byte length + 1-byte type + 1-byte flags
// + 4-byte stream ID) as defined in RFC 7540.
func IsHTTP2(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Explicit HTTP/2 connection preface (cleartext upgrade or direct h2)
	if bytes.HasPrefix(data, http2Preface) {
		return true
	}
	// Binary frame: need at least 9 bytes (frame header)
	if len(data) >= 9 {
		frameLen := binary.BigEndian.Uint32(append([]byte{0}, data[:3]...)) // 24-bit BE
		frameType := data[3]
		// Stream ID is in data[5:9] (top bit reserved); flags in data[4].
		// Accept if frame type is a known HTTP/2 type and frame length is plausible.
		if http2FrameTypes[frameType] && frameLen < 16777216 {
			_ = frameLen
			return true
		}
	}
	return false
}

// extractHeader returns the trimmed value of the first occurrence of
// headerName (case-insensitive) in the raw HTTP headers section.
func extractHeader(data []byte, headerName string) string {
	prefix := []byte(headerName + ":")
	prefixLower := bytes.ToLower(prefix)

	lines := bytes.SplitN(data, []byte("\n"), 64)
	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) < len(prefix) {
			continue
		}
		if bytes.EqualFold(trimmed[:len(prefix)], prefixLower) {
			val := bytes.TrimSpace(trimmed[len(prefix):])
			// Strip trailing \r if present.
			if len(val) > 0 && val[len(val)-1] == '\r' {
				val = val[:len(val)-1]
			}
			return string(val)
		}
	}
	return ""
}
