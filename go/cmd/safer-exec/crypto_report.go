package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// emitCryptoResult publishes a run's crypto observations: cipher-violation
// entries for ciphers outside cfg.AllowCiphers, the crypto-* audit entries
// (with enableAudit), the CRYPTO: result and the CBOM file.
func emitCryptoResult(cfg config.ExecConfig, r *config.CryptoResult) {
	if r == nil {
		return
	}
	if r.Libraries == nil {
		r.Libraries = []config.CryptoLibrary{}
	}
	if r.Ciphers == nil {
		r.Ciphers = []config.CipherInfo{}
	}
	if r.Operations == nil {
		r.Operations = []config.CryptoOperation{}
	}
	checkAllowedCiphers(cfg, r.Ciphers)
	if cfg.EnableAudit {
		logAuditCryptoResult(r)
	}
	if data, err := json.Marshal(r); err == nil {
		writeStructured(cfg, "CRYPTO:", data)
	}
	if cfg.CBOMOutputPath != "" {
		writeCBOMFile(cfg.CBOMOutputPath, r)
	}
}

// withProxyCiphers adds the TLS parameters the egress proxy observed to r
// (creating it for platform when nil).
func withProxyCiphers(r *config.CryptoResult, platform string, p *egressProxy) *config.CryptoResult {
	if r == nil {
		r = &config.CryptoResult{Platform: platform}
	}
	r.Ciphers = append(r.Ciphers, p.cipherSnapshot()...)
	return r
}

// checkAllowedCiphers reports ciphers outside the allowCiphers list. It is an
// audit, not a block: the connection has already been made.
func checkAllowedCiphers(cfg config.ExecConfig, ciphers []config.CipherInfo) {
	if len(cfg.AllowCiphers) == 0 {
		return
	}
	allowed := make(map[string]bool, len(cfg.AllowCiphers))
	for _, c := range cfg.AllowCiphers {
		allowed[c] = true
	}
	for _, c := range ciphers {
		if allowed[c.Name] || allowed[c.IANAName] {
			continue
		}
		target := c.Name
		details := fmt.Sprintf("cipher %s (IANA: %s) is not allowed by policy", c.Name, c.IANAName)
		if c.Host != "" {
			details += " (" + c.Host + ")"
		}
		if data, err := json.Marshal(map[string]string{"type": "cipher-violation", "target": target, "details": details}); err == nil {
			emitAuditLine(data, os.Stderr)
		}
		fmt.Fprintf(os.Stderr, "safer-exec: cipher-violation: %s\n", details)
	}
}

// logAuditCryptoResult emits audit entries for ciphers, libraries, and
// operations.
func logAuditCryptoResult(r *config.CryptoResult) {
	for _, c := range r.Ciphers {
		entry := map[string]any{
			"type":           "crypto-cipher",
			"name":           c.Name,
			"ianaName":       c.IANAName,
			"ianaId":         c.IANAID,
			"protocol":       c.Protocol,
			"bits":           c.Bits,
			"keyExchange":    c.KeyExchange,
			"authentication": c.Authentication,
			"encryption":     c.Encryption,
			"encryptionBits": c.EncryptionBits,
			"hash":           c.Hash,
			"mode":           c.Mode,
			"library":        c.Library,
			"libraryVersion": c.LibraryVersion,
			"pid":            c.PID,
		}
		for k, v := range map[string]string{
			"group": c.Group, "host": c.Host, "serverName": c.ServerName,
			"serverKey": c.ServerKey, "certSignature": c.CertSignature, "source": c.Source,
		} {
			if v != "" {
				entry[k] = v
			}
		}
		if c.PostQuantum {
			entry["postQuantum"] = true
		}
		if c.ECH {
			entry["ech"] = true
		}
		if data, err := json.Marshal(entry); err == nil {
			emitAuditLine(data, os.Stderr)
		}
	}
	for _, l := range r.Libraries {
		entry := map[string]any{
			"type":    "crypto-library",
			"name":    l.Name,
			"version": l.Version,
			"path":    l.Path,
			"source":  l.Source,
		}
		if data, err := json.Marshal(entry); err == nil {
			emitAuditLine(data, os.Stderr)
		}
	}
	for _, o := range r.Operations {
		entry := map[string]any{
			"type":           "crypto-operation",
			"operation":      o.Type,
			"algorithm":      o.Algorithm,
			"library":        o.Library,
			"libraryVersion": o.LibraryVersion,
			"pid":            o.PID,
			"count":          o.Count,
		}
		if data, err := json.Marshal(entry); err == nil {
			emitAuditLine(data, os.Stderr)
		}
	}
}
