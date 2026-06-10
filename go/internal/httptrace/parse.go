package httptrace

import (
	"bytes"
	"strings"

	"golang.org/x/net/http2/hpack"
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
// captured from a TLS write buffer. Returns (method, path, query, host, body, true) on
// success or ("", "", "", "", "", false) when the buffer doesn't look like HTTP/1.x.
//
// Only the first request line and the Host header are extracted; the body
// and subsequent pipelined requests are ignored.
func ParseHTTPRequest(data []byte) (method, path, query, host, body string, ok bool) {
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

	if idx := strings.Index(path, "?"); idx >= 0 {
		query = path[idx+1:]
		path = path[:idx]
	}

	// Scan headers for "Host:".
	headers := data[lineEnd+1:]
	host = extractHeader(headers, "Host")

	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd >= 0 {
		body = string(data[headerEnd+4:])
	} else if headerEnd = bytes.Index(data, []byte("\n\n")); headerEnd >= 0 {
		body = string(data[headerEnd+2:])
	}
	body = strings.TrimSpace(body)
	if len(body) > 1024 {
		body = body[:1024]
	}

	ok = true
	return
}

// http2Preface is the fixed 24-byte client connection preface for HTTP/2 (RFC 7540 §3.5).
var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// http2NonDataFrameTypes is the subset of HTTP/2 frame types (RFC 7540 §6) used
// for binary H2 detection.  DATA (0x0) is excluded because its 3-byte length
// field can collide with TLS record headers (content-type + version bytes).
var http2NonDataFrameTypes = map[byte]bool{
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
//
// DATA frames (type 0x0) are intentionally excluded from the binary-frame
// heuristic because their length encoding overlaps with TLS record headers.
func IsHTTP2(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Explicit HTTP/2 connection preface (cleartext upgrade or direct h2)
	if bytes.HasPrefix(data, http2Preface) {
		return true
	}
	// Binary frame: need at least 9 bytes (frame header).
	// Only non-DATA frame types are considered to avoid false positives with
	// TLS record headers whose content-type/version bytes map to type=0.
	if len(data) >= 9 {
		frameLen := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
		frameType := data[3]
		if http2NonDataFrameTypes[frameType] && frameLen < 16777216 {
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

const (
	http2FrameTypeHeaders      = 0x1
	http2FrameTypeContinuation = 0x9
	http2FrameHeaderLen        = 9 // 3-byte length + 1-byte type + 1-byte flags + 4-byte stream ID
)

// ParseHTTP2Frames scans data for HTTP/2 HEADERS frames (RFC 7540 §6.2) and
// feeds their block fragments into dec for HPACK decoding (RFC 7541).
//
// dec must be a per-connection *hpack.Decoder maintained by the caller across
// successive TLS writes so that the dynamic table stays consistent.
//
// Returns (method, path, query, host, true) from the first HEADERS frame that
// contains at least the :method and :path pseudo-headers, or false if no
// usable HEADERS frame was found.
//
// The function skips the 24-byte HTTP/2 client connection preface if present,
// handles HEADERS frames with the PADDED and PRIORITY flags, and advances
// through multiple frames in a single buffer.
func ParseHTTP2Frames(data []byte, dec *hpack.Decoder) (method, path, query, host string, ok bool) {
	// Skip the connection preface emitted on the first write of a new h2 session.
	data = bytes.TrimPrefix(data, http2Preface)

	for len(data) >= http2FrameHeaderLen {
		// Parse 9-byte frame header.
		frameLen := int(uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2]))
		frameType := data[3]
		frameFlags := data[4]
		// Stream ID occupies data[5:9]; top bit is reserved.

		total := http2FrameHeaderLen + frameLen
		if total > len(data) {
			// Truncated frame — captured buffer ended mid-frame.
			break
		}

		payload := data[http2FrameHeaderLen:total]
		data = data[total:]

		if frameType != http2FrameTypeHeaders && frameType != http2FrameTypeContinuation {
			continue
		}

		blockFrag := payload

		if frameType == http2FrameTypeHeaders {
			// PADDED flag (0x8): first byte is pad length; strip it and the trailing pad.
			if frameFlags&0x8 != 0 {
				if len(blockFrag) == 0 {
					continue
				}
				padLen := int(blockFrag[0])
				blockFrag = blockFrag[1:]
				if padLen >= len(blockFrag) {
					continue
				}
				blockFrag = blockFrag[:len(blockFrag)-padLen]
			}
			// PRIORITY flag (0x20): 5 bytes of stream dependency + weight.
			if frameFlags&0x20 != 0 {
				if len(blockFrag) < 5 {
					continue
				}
				blockFrag = blockFrag[5:]
			}
		}

		// Feed the block fragment into the HPACK decoder.
		// The decoder accumulates dynamic table state across calls.
		fields, err := dec.DecodeFull(blockFrag)
		if err != nil {
			// Malformed HPACK or mid-stream capture — skip this frame.
			continue
		}

		var m, p, h string
		for _, f := range fields {
			switch f.Name {
			case ":method":
				m = f.Value
			case ":path":
				p = f.Value
			case ":authority":
				h = f.Value
			case "host":
				if h == "" {
					h = f.Value
				}
			}
		}

		if m != "" && p != "" {
			var q string
			if idx := strings.Index(p, "?"); idx >= 0 {
				q = p[idx+1:]
				p = p[:idx]
			}
			return m, p, q, h, true
		}
	}
	return
}
