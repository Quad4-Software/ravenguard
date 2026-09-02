// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package tlscerts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"
)

func TestManualStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewManualStore(filepath.Join(dir, "manual"))
	if err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM := mustSelfSigned(t, "app.example.com")
	if err := store.Put("App.Example.COM", string(certPEM), string(keyPEM)); err != nil {
		t.Fatal(err)
	}

	chi := &tls.ClientHelloInfo{ServerName: "app.example.com"}
	got, err := store.GetCertificate(chi)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Leaf == nil {
		t.Fatal("expected certificate")
	}
	if got.Leaf.Subject.CommonName != "app.example.com" {
		t.Fatalf("cn = %q", got.Leaf.Subject.CommonName)
	}

	detail, err := store.Detail("app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if detail.Source != SourceManual || detail.Hostname != "app.example.com" {
		t.Fatalf("detail = %#v", detail)
	}
	if detail.FingerprintSHA256 == "" || detail.Subject == "" {
		t.Fatalf("missing fields: %#v", detail)
	}
	if len(store.List()) != 1 {
		t.Fatalf("list len = %d", len(store.List()))
	}

	if err := store.Delete("app.example.com"); err != nil {
		t.Fatal(err)
	}
	miss, err := store.GetCertificate(chi)
	if err != nil {
		t.Fatal(err)
	}
	if miss != nil {
		t.Fatal("expected miss after delete")
	}
	if _, err := store.Detail("app.example.com"); err == nil {
		t.Fatal("expected detail error after delete")
	}
}

func TestManualStoreReload(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "manual")
	store, err := NewManualStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := mustSelfSigned(t, "reload.example")
	if err := store.Put("reload.example", string(certPEM), string(keyPEM)); err != nil {
		t.Fatal(err)
	}

	store2, err := NewManualStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store2.GetCertificate(&tls.ClientHelloInfo{ServerName: "reload.example"})
	if err != nil || got == nil {
		t.Fatalf("reload miss: %v %#v", err, got)
	}
}

func mustSelfSigned(t *testing.T, host string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{host},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM
}
