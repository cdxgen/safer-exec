package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// withReport points the report channel at a pipe for the test and returns a
// function that closes it and returns the lines written.
func withReport(t *testing.T) func() []string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := reportOut
	reportOut = w
	lines := make(chan []string, 1)
	go func() {
		var out []string
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
		for sc.Scan() {
			out = append(out, sc.Text())
		}
		lines <- out
	}()
	return func() []string {
		reportOut = prev
		w.Close()
		out := <-lines
		r.Close()
		return out
	}
}

func TestReportChannelFormat(t *testing.T) {
	done := withReport(t)
	emitAuditLine([]byte(`{"type":"lib-load","target":"/lib/libc.so.6"}`), os.Stderr)
	emitAuditLine([]byte(`not json`), os.Stderr)
	writeStructured(config.ExecConfig{}, "FSDIFF:", []byte(`{"added":[]}`))
	writeStructured(config.ExecConfig{}, "PROFILE:", []byte("(version 1)\n(deny default)"))
	lines := done()

	want := []string{
		`{"audit":{"type":"lib-load","target":"/lib/libc.so.6"}}`,
		`{"result":"FSDIFF","data":{"added":[]}}`,
		`{"result":"PROFILE","data":"(version 1)\n(deny default)"}`,
	}
	if len(lines) != len(want) {
		t.Fatalf("lines = %q", lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %s, want %s", i, lines[i], want[i])
		}
	}
}

func TestStructuredFallbackWithoutReport(t *testing.T) {
	if reportActive() {
		t.Skip("report channel open")
	}
	path := filepath.Join(t.TempDir(), "structured.log")
	writeStructured(config.ExecConfig{StructuredOutputPath: path}, "DRYRUN:", []byte(`{"events":[]}`))
	data, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(data)) != `DRYRUN:{"events":[]}` {
		t.Fatalf("structured file = %q (%v)", data, err)
	}
}

func TestCryptoResultAndCBOM(t *testing.T) {
	cbom := filepath.Join(t.TempDir(), "cbom.json")
	cfg := config.ExecConfig{EnableAudit: true, CBOMOutputPath: cbom, AllowCiphers: []string{"TLS_AES_256_GCM_SHA384"}}
	r := &config.CryptoResult{Platform: "windows",
		Libraries: []config.CryptoLibrary{{Name: "Windows Schannel", Version: "10.0.26100.1", Path: `C:\Windows\System32\schannel.dll`, Source: "etw_image_load"}},
		Ciphers: []config.CipherInfo{
			{Name: "TLS_AES_128_GCM_SHA256", IANAName: "TLS_AES_128_GCM_SHA256", IANAID: 0x1301, Protocol: "TLSv1.3", Encryption: "AES", EncryptionBits: 128, Mode: "GCM", Hash: "SHA256",
				KeyExchange: "ECDHE+ML-KEM", Group: "X25519MLKEM768", PostQuantum: true, Host: "registry.npmjs.org:443", Source: "proxy"},
			{Name: "ECDHE-RSA-AES128-GCM-SHA256", IANAName: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Protocol: "TLSv1.2", KeyExchange: "ECDHE", Authentication: "RSA",
				Encryption: "AES", EncryptionBits: 128, Mode: "GCM", Hash: "SHA256", Group: "secp256r1", ServerKey: "RSA-2048", Host: "example.org:443", Source: "proxy"},
		}}
	done := withReport(t)
	emitCryptoResult(cfg, r)
	lines := done()

	var audits []map[string]any
	var crypto *config.CryptoResult
	for _, l := range lines {
		var msg struct {
			Audit  map[string]any  `json:"audit"`
			Result string          `json:"result"`
			Data   json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal([]byte(l), &msg); err != nil {
			t.Fatalf("bad line %q", l)
		}
		if msg.Audit != nil {
			audits = append(audits, msg.Audit)
		} else if msg.Result == "CRYPTO" {
			crypto = &config.CryptoResult{}
			_ = json.Unmarshal(msg.Data, crypto)
		}
	}
	var violations, ciphers, libs int
	for _, a := range audits {
		switch a["type"] {
		case "cipher-violation":
			violations++
		case "crypto-cipher":
			ciphers++
			if a["group"] == "X25519MLKEM768" && a["postQuantum"] != true {
				t.Errorf("post-quantum flag missing: %v", a)
			}
		case "crypto-library":
			libs++
		}
	}
	if violations != 2 || ciphers != 2 || libs != 1 || crypto == nil || len(crypto.Ciphers) != 2 {
		t.Fatalf("violations=%d ciphers=%d libs=%d crypto=%+v", violations, ciphers, libs, crypto)
	}

	data, err := os.ReadFile(cbom)
	if err != nil {
		t.Fatal(err)
	}
	var doc cbomDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	byName := map[string]cbomComponent{}
	for _, c := range doc.Components {
		byName[c.Name] = c
	}
	// The hybrid X25519MLKEM768 is recorded as its two halves.
	kem := byName["ML-KEM-768"]
	if kem.CryptoProperties == nil || kem.CryptoProperties.AlgorithmProperties.Primitive != "kem" || kem.CryptoProperties.AlgorithmProperties.NistQuantumSecurityLevel != 3 {
		t.Errorf("ML-KEM half of the hybrid group = %+v", kem.CryptoProperties)
	}
	if c := byName["secp256r1"]; c.CryptoProperties == nil || c.CryptoProperties.AlgorithmProperties.Primitive != "key-agree" {
		t.Errorf("classical group component = %+v", c)
	}
	for _, name := range []string{"x25519", "RSA-2048", "Windows Schannel", "TLSv1.3", "TLSv1.2"} {
		if _, ok := byName[name]; !ok {
			t.Errorf("CBOM lacks %s: %v", name, doc.Components)
		}
	}
}
