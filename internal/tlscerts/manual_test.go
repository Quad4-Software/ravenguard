// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package tlscerts

import (
	"crypto/tls"
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
	if detail.Source != SourceSelfSigned || detail.Hostname != "app.example.com" {
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
	certPEM, keyPEM, err := Generate(GenerateOptions{
		Hosts:    []string{host},
		Validity: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM
}
