// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package tlscerts

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseValidity(t *testing.T) {
	d, err := ParseValidity("365d")
	if err != nil || d != 365*24*time.Hour {
		t.Fatalf("365d: %v %v", d, err)
	}
	d, err = ParseValidity("48h")
	if err != nil || d != 48*time.Hour {
		t.Fatalf("48h: %v %v", d, err)
	}
	d, err = ParseValidity("")
	if err != nil || d != defaultSelfSignedValidity {
		t.Fatalf("empty: %v %v", d, err)
	}
	if _, err := ParseValidity("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestGenerateRoundTrip(t *testing.T) {
	certPEM, keyPEM, err := Generate(GenerateOptions{
		Hosts:    []string{"app.example.com", "www.example.com"},
		IPs:      []net.IP{net.ParseIP("127.0.0.1")},
		Validity: 48 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureLeaf(&cert); err != nil {
		t.Fatal(err)
	}
	if !IsSelfSigned(cert.Leaf) {
		t.Fatal("expected self-signed")
	}
	if cert.Leaf.Subject.CommonName != "app.example.com" {
		t.Fatalf("cn = %q", cert.Leaf.Subject.CommonName)
	}
	if err := cert.Leaf.VerifyHostname("www.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := cert.Leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if SourceForLeaf(cert.Leaf, SourceManual) != SourceSelfSigned {
		t.Fatal("expected SourceSelfSigned")
	}
}

func TestGenerateParsesHostAsIP(t *testing.T) {
	certPEM, keyPEM, err := Generate(GenerateOptions{
		Hosts: []string{"localhost", "127.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureLeaf(&cert); err != nil {
		t.Fatal(err)
	}
	if err := cert.Leaf.VerifyHostname("localhost"); err != nil {
		t.Fatal(err)
	}
	if err := cert.Leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureFilesReuseAndRegenerate(t *testing.T) {
	dir := t.TempDir()
	opts := GenerateOptions{Hosts: []string{"reuse.example"}, Validity: 30 * 24 * time.Hour}

	cert1, key1, err := EnsureFiles(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	cert2, key2, err := EnsureFiles(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	if string(cert1) != string(cert2) || string(key1) != string(key2) {
		t.Fatal("expected reuse of existing files")
	}

	opts2 := GenerateOptions{Hosts: []string{"other.example"}, Validity: 30 * 24 * time.Hour}
	cert3, _, err := EnsureFiles(dir, opts2)
	if err != nil {
		t.Fatal(err)
	}
	if string(cert1) == string(cert3) {
		t.Fatal("expected regenerate for different hosts")
	}

	block, _ := pem.Decode(cert3)
	if block == nil {
		t.Fatal("decode cert")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("other.example"); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureFilesRegenerateNearExpiry(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, err := Generate(GenerateOptions{
		Hosts:     []string{"expire.example"},
		Validity:  2 * time.Hour,
		NotBefore: time.Now().Add(-90 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "privkey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	newCert, _, err := EnsureFiles(dir, GenerateOptions{
		Hosts:    []string{"expire.example"},
		Validity: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(newCert) == string(certPEM) {
		t.Fatal("expected regenerate near expiry")
	}
}

func TestWriteFilesForce(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	certPEM, keyPEM, err := Generate(GenerateOptions{Hosts: []string{"cli.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFiles(certPath, keyPath, certPEM, keyPEM, false); err != nil {
		t.Fatal(err)
	}
	if err := WriteFiles(certPath, keyPath, certPEM, keyPEM, false); err == nil {
		t.Fatal("expected exists error")
	}
	cert2, key2, err := Generate(GenerateOptions{Hosts: []string{"cli2.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFiles(certPath, keyPath, cert2, key2, true); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(cert2) {
		t.Fatal("force write did not replace")
	}
}
