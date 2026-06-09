package httptrace

import "testing"

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
