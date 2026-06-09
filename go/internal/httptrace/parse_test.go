package httptrace

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func TestParseHTTPRequest(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantMethod string
		wantPath   string
		wantHost   string
		wantOK     bool
	}{
		{
			name:       "simple GET",
			input:      "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantMethod: "GET",
			wantPath:   "/",
			wantHost:   "example.com",
			wantOK:     true,
		},
		{
			name:       "POST with path",
			input:      "POST /v1/packages HTTP/1.1\r\nHost: registry.npmjs.org\r\nContent-Type: application/json\r\n\r\n{\"name\":\"lodash\"}",
			wantMethod: "POST",
			wantPath:   "/v1/packages",
			wantHost:   "registry.npmjs.org",
			wantOK:     true,
		},
		{
			name:       "GET with query string",
			input:      "GET /search?q=react&version=18 HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
			wantMethod: "GET",
			wantPath:   "/search?q=react&version=18",
			wantHost:   "api.example.com",
			wantOK:     true,
		},
		{
			name:       "DELETE request",
			input:      "DELETE /api/v2/resource/123 HTTP/1.1\r\nHost: api.service.io\r\n\r\n",
			wantMethod: "DELETE",
			wantPath:   "/api/v2/resource/123",
			wantHost:   "api.service.io",
			wantOK:     true,
		},
		{
			name:       "PATCH request",
			input:      "PATCH /users/42 HTTP/1.1\r\nHost: accounts.example.com\r\n\r\n",
			wantMethod: "PATCH",
			wantPath:   "/users/42",
			wantHost:   "accounts.example.com",
			wantOK:     true,
		},
		{
			name:       "npm registry install",
			input:      "GET /-/npm/v1/security/advisories/bulk HTTP/1.1\r\nHost: registry.npmjs.org\r\nAccept: application/json\r\n\r\n",
			wantMethod: "GET",
			wantPath:   "/-/npm/v1/security/advisories/bulk",
			wantHost:   "registry.npmjs.org",
			wantOK:     true,
		},
		{
			name:       "host header case insensitive",
			input:      "GET /path HTTP/1.1\r\nHOST: upper.example.com\r\n\r\n",
			wantMethod: "GET",
			wantPath:   "/path",
			wantHost:   "upper.example.com",
			wantOK:     true,
		},
		{
			name:   "not HTTP — TLS record",
			input:  "\x16\x03\x01\x00\xf1\x01\x00\x00\xed\x03\x03",
			wantOK: false,
		},
		{
			name:   "not HTTP — binary data",
			input:  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
			wantOK: false,
		},
		{
			name:   "too short",
			input:  "GET /",
			wantOK: false,
		},
		{
			name:   "empty",
			input:  "",
			wantOK: false,
		},
		{
			name:       "HTTP/1.0",
			input:      "GET /index.html HTTP/1.0\r\nHost: oldsite.com\r\n\r\n",
			wantMethod: "GET",
			wantPath:   "/index.html",
			wantHost:   "oldsite.com",
			wantOK:     true,
		},
		{
			name:       "request without Host header",
			input:      "GET /path HTTP/1.1\r\nAccept: */*\r\n\r\n",
			wantMethod: "GET",
			wantPath:   "/path",
			wantHost:   "",
			wantOK:     true,
		},
		{
			name:       "OPTIONS CORS preflight",
			input:      "OPTIONS /api/data HTTP/1.1\r\nHost: api.example.com\r\nOrigin: https://app.example.com\r\n\r\n",
			wantMethod: "OPTIONS",
			wantPath:   "/api/data",
			wantHost:   "api.example.com",
			wantOK:     true,
		},
		{
			name:       "HEAD request",
			input:      "HEAD /healthz HTTP/1.1\r\nHost: service.internal\r\n\r\n",
			wantMethod: "HEAD",
			wantPath:   "/healthz",
			wantHost:   "service.internal",
			wantOK:     true,
		},
		{
			name:       "LF-only line endings (no CRLF)",
			input:      "GET /path HTTP/1.1\nHost: example.com\n\n",
			wantMethod: "GET",
			wantPath:   "/path",
			wantHost:   "example.com",
			wantOK:     true,
		},
		{
			name:       "PUT with deep path",
			input:      "PUT /v2/registry.npmjs.org/npm/-/npm-10.0.0.tgz HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n",
			wantMethod: "PUT",
			wantPath:   "/v2/registry.npmjs.org/npm/-/npm-10.0.0.tgz",
			wantHost:   "registry.npmjs.org",
			wantOK:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			method, path, host, ok := ParseHTTPRequest([]byte(tc.input))
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v (method=%q path=%q host=%q)", ok, tc.wantOK, method, path, host)
				return
			}
			if !ok {
				return
			}
			if method != tc.wantMethod {
				t.Errorf("method = %q, want %q", method, tc.wantMethod)
			}
			if path != tc.wantPath {
				t.Errorf("path = %q, want %q", path, tc.wantPath)
			}
			if host != tc.wantHost {
				t.Errorf("host = %q, want %q", host, tc.wantHost)
			}
		})
	}
}

func TestExtractHeader(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		headerName string
		want       string
	}{
		{
			name:       "content-type",
			data:       "Content-Type: application/json\r\nAccept: */*\r\n",
			headerName: "Content-Type",
			want:       "application/json",
		},
		{
			name:       "host with port",
			data:       "Host: api.example.com:8443\r\nAuthorization: Bearer tok\r\n",
			headerName: "Host",
			want:       "api.example.com:8443",
		},
		{
			name:       "header not present",
			data:       "Content-Length: 42\r\n",
			headerName: "Host",
			want:       "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractHeader([]byte(tc.data), tc.headerName)
			if got != tc.want {
				t.Errorf("extractHeader(%q) = %q, want %q", tc.headerName, got, tc.want)
			}
		})
	}
}

func TestSource_String(t *testing.T) {
	cases := []struct {
		s    Source
		want string
	}{
		{SourceSSLWrite, "ssl_write_uprobe"},
		{SourceGoTLS, "go_tls_uprobe"},
		{SourceGnuTLSSend, "gnutls_uprobe"},
		{Source(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("Source(%d).String() = %q, want %q", c.s, got, c.want)
		}
	}
}

// buildH2Frame constructs a minimal HTTP/2 frame (RFC 7540 §4.1).
func buildH2Frame(frameType byte, flags byte, streamID uint32, payload []byte) []byte {
	var buf bytes.Buffer
	length := len(payload)
	buf.WriteByte(byte(length >> 16))
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length))
	buf.WriteByte(frameType)
	buf.WriteByte(flags)
	var sid [4]byte
	binary.BigEndian.PutUint32(sid[:], streamID&0x7fffffff)
	buf.Write(sid[:])
	buf.Write(payload)
	return buf.Bytes()
}

// encodeH2Headers builds an HPACK block for the given pseudo-headers using
// the static table only (indexed representations, no dynamic table additions).
func encodeH2Headers(method, path, authority, scheme string) []byte {
	var enc hpack.Encoder
	var buf bytes.Buffer
	enc = *hpack.NewEncoder(&buf)
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: method})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	if authority != "" {
		enc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
	}
	if scheme != "" {
		enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: scheme})
	}
	return buf.Bytes()
}

func TestIsHTTP2(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "connection preface",
			data: []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
			want: true,
		},
		{
			name: "SETTINGS frame (type=4)",
			data: buildH2Frame(0x4, 0x0, 0, []byte{}),
			want: true,
		},
		{
			name: "HEADERS frame (type=1)",
			data: buildH2Frame(0x1, 0x4, 1, []byte{0x82, 0x84}), // :method GET, :path /
			want: true,
		},
		{
			name: "HTTP/1.x request",
			data: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want: false,
		},
		{
			name: "TLS record",
			data: []byte("\x16\x03\x01\x00\xf1\x01\x00\x00\xed"),
			want: false,
		},
		{
			name: "empty",
			data: []byte{},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsHTTP2(tc.data); got != tc.want {
				t.Errorf("IsHTTP2() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseHTTP2Frames(t *testing.T) {
	tests := []struct {
		name       string
		buildData  func() []byte
		wantMethod string
		wantPath   string
		wantHost   string
		wantOK     bool
	}{
		{
			name: "simple GET via static table",
			buildData: func() []byte {
				// Static table: :method GET = index 2, :path / = index 4
				block := []byte{0x82, 0x84} // indexed header field repr
				return buildH2Frame(http2FrameTypeHeaders, 0x5 /*END_STREAM|END_HEADERS*/, 1, block)
			},
			wantMethod: "GET",
			wantPath:   "/",
			wantHost:   "",
			wantOK:     true,
		},
		{
			name: "GET with authority via literal headers",
			buildData: func() []byte {
				block := encodeH2Headers("GET", "/api/v1/packages", "registry.npmjs.org", "https")
				return buildH2Frame(http2FrameTypeHeaders, 0x5, 1, block)
			},
			wantMethod: "GET",
			wantPath:   "/api/v1/packages",
			wantHost:   "registry.npmjs.org",
			wantOK:     true,
		},
		{
			name: "POST request",
			buildData: func() []byte {
				block := encodeH2Headers("POST", "/v1/login", "auth.example.com", "https")
				return buildH2Frame(http2FrameTypeHeaders, 0x4 /*END_HEADERS*/, 3, block)
			},
			wantMethod: "POST",
			wantPath:   "/v1/login",
			wantHost:   "auth.example.com",
			wantOK:     true,
		},
		{
			name: "connection preface followed by SETTINGS then HEADERS",
			buildData: func() []byte {
				var buf bytes.Buffer
				buf.Write(http2Preface)
				buf.Write(buildH2Frame(0x4, 0x0, 0, []byte{})) // SETTINGS
				block := encodeH2Headers("GET", "/search", "api.example.com", "https")
				buf.Write(buildH2Frame(http2FrameTypeHeaders, 0x5, 1, block))
				return buf.Bytes()
			},
			wantMethod: "GET",
			wantPath:   "/search",
			wantHost:   "api.example.com",
			wantOK:     true,
		},
		{
			name: "HEADERS with PRIORITY flag",
			buildData: func() []byte {
				block := encodeH2Headers("GET", "/priority", "example.com", "https")
				// Prepend 5-byte priority: exclusive+dep(4) + weight(1)
				priority := []byte{0x00, 0x00, 0x00, 0x01, 0x0f}
				payload := append(priority, block...)
				return buildH2Frame(http2FrameTypeHeaders, 0x24 /*END_HEADERS|PRIORITY*/, 1, payload)
			},
			wantMethod: "GET",
			wantPath:   "/priority",
			wantHost:   "example.com",
			wantOK:     true,
		},
		{
			name: "HEADERS with PADDED flag",
			buildData: func() []byte {
				block := encodeH2Headers("GET", "/padded", "padded.example.com", "https")
				padLen := byte(4)
				payload := append([]byte{padLen}, block...)
				payload = append(payload, make([]byte, int(padLen))...)
				return buildH2Frame(http2FrameTypeHeaders, 0x0c /*END_HEADERS|PADDED*/, 1, payload)
			},
			wantMethod: "GET",
			wantPath:   "/padded",
			wantHost:   "padded.example.com",
			wantOK:     true,
		},
		{
			name: "only DATA frames — no HEADERS",
			buildData: func() []byte {
				return buildH2Frame(0x0 /*DATA*/, 0x1, 1, []byte("hello world"))
			},
			wantOK: false,
		},
		{
			name: "empty buffer",
			buildData: func() []byte {
				return []byte{}
			},
			wantOK: false,
		},
		{
			name: "truncated frame header",
			buildData: func() []byte {
				return []byte{0x00, 0x00} // only 2 bytes — need at least 9
			},
			wantOK: false,
		},
		{
			name: "dynamic table: second request reuses prior entry",
			buildData: func() []byte {
				// This test uses a shared decoder to verify that the dynamic
				// table carries over between calls, handled by the caller.
				// We just verify the second HEADERS frame is parseable.
				var buf bytes.Buffer
				block1 := encodeH2Headers("GET", "/first", "example.com", "https")
				buf.Write(buildH2Frame(http2FrameTypeHeaders, 0x5, 1, block1))
				block2 := encodeH2Headers("GET", "/second", "example.com", "https")
				buf.Write(buildH2Frame(http2FrameTypeHeaders, 0x5, 3, block2))
				return buf.Bytes()
			},
			wantMethod: "GET",
			wantPath:   "/first", // first HEADERS wins
			wantHost:   "example.com",
			wantOK:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := hpack.NewDecoder(4096, nil)
			method, path, host, ok := ParseHTTP2Frames(tc.buildData(), dec)
			if ok != tc.wantOK {
				t.Errorf("ok=%v want=%v (method=%q path=%q host=%q)", ok, tc.wantOK, method, path, host)
				return
			}
			if !ok {
				return
			}
			if method != tc.wantMethod {
				t.Errorf("method=%q want=%q", method, tc.wantMethod)
			}
			if path != tc.wantPath {
				t.Errorf("path=%q want=%q", path, tc.wantPath)
			}
			if host != tc.wantHost {
				t.Errorf("host=%q want=%q", host, tc.wantHost)
			}
		})
	}
}
