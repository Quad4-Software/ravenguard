// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package tlsacme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestNewRequiresAgreeTOS(t *testing.T) {
	_, err := New(Config{
		Email:      "ops@example.com",
		StorageDir: t.TempDir(),
		AgreeTOS:   false,
	})
	if err == nil {
		t.Fatal("expected error when AgreeTOS is false")
	}
	if !strings.Contains(err.Error(), "AgreeTOS") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewRequiresEmail(t *testing.T) {
	_, err := New(Config{
		Email:      "",
		StorageDir: t.TempDir(),
		AgreeTOS:   true,
	})
	if err == nil {
		t.Fatal("expected error when Email is empty")
	}
	if !strings.Contains(err.Error(), "Email") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFillHostCertFromLeaf(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "leaf.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
		DNSNames:     []string{"leaf.example", "www.leaf.example"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	st := HostCertStatus{Hostname: "leaf.example", State: StateActive}
	fillHostCertFromLeaf(&st, leaf)
	if st.Source != "acme" {
		t.Fatalf("source = %q", st.Source)
	}
	if st.Subject == "" || st.Serial == "" || st.FingerprintSHA256 == "" {
		t.Fatalf("missing fields: %#v", st)
	}
	if st.DaysLeft < 1 {
		t.Fatalf("days_left = %d", st.DaysLeft)
	}
	if len(st.DNSNames) != 2 {
		t.Fatalf("dns = %#v", st.DNSNames)
	}
	if st.NotBefore.IsZero() || st.NotAfter.IsZero() {
		t.Fatal("expected not_before/not_after")
	}
}

func TestManagerGetCertificateNilSafe(t *testing.T) {
	var m *Manager
	cert, err := m.GetCertificate(nil)
	if cert != nil || err != nil {
		t.Fatalf("got %v %v", cert, err)
	}
}
