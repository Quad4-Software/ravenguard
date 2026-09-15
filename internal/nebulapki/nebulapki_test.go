// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package nebulapki

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

func TestGenerateCAAndSignHost(t *testing.T) {
	caPEM, keyPEM, fp, err := GenerateCA("testca", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if fp == "" {
		t.Fatal("empty fingerprint")
	}
	ca, err := ParseCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if ca.Name() != "testca" || ca.Fingerprint() != fp {
		t.Fatalf("ca mismatch: name=%s fp=%s", ca.Name(), ca.Fingerprint())
	}

	network := netip.MustParsePrefix("10.42.0.5/24")
	certPEM, keyPEM, hostFP, notAfter, err := ca.SignHost("edge-1", network, []string{"edges"}, time.Hour, 2)
	if err != nil {
		t.Fatal(err)
	}
	if hostFP == "" || hostFP == fp {
		t.Fatal("bad host fingerprint")
	}
	if notAfter.Before(time.Now()) {
		t.Fatal("host cert already expired")
	}

	// The issued cert must verify against the CA pool.
	nc, _, err := cert.UnmarshalCertificateFromPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	caPool, err := cert.NewCAPoolFromPEM(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := caPool.VerifyCertificate(time.Now(), nc); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if nc.Name() != "edge-1" {
		t.Fatalf("name: %q", nc.Name())
	}
	if got := nc.Networks(); len(got) != 1 || got[0] != network {
		t.Fatalf("networks: %v", got)
	}
	if len(nc.Groups()) != 1 || nc.Groups()[0] != "edges" {
		t.Fatalf("groups: %v", nc.Groups())
	}

	// The key must match the cert public key.
	key, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.VerifyPrivateKey(curve, key); err != nil {
		t.Fatalf("keypair: %v", err)
	}
}

func TestSignHostClampsToCAExpiry(t *testing.T) {
	caPEM, keyPEM, _, err := GenerateCA("short", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	network := netip.MustParsePrefix("10.42.0.9/24")
	_, _, _, notAfter, err := ca.SignHost("h", network, nil, 24*time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if notAfter.After(ca.NotAfter()) {
		t.Fatalf("notAfter %s beyond ca %s", notAfter, ca.NotAfter())
	}
}

func TestAllocateIP(t *testing.T) {
	pool := netip.MustParsePrefix("10.42.0.0/24")
	used := map[string]struct{}{}
	p, err := AllocateIP(pool, used)
	if err != nil {
		t.Fatal(err)
	}
	if p.Addr().String() != "10.42.0.1" || p.Bits() != 24 {
		t.Fatalf("first alloc: %s", p)
	}
	used[p.Addr().String()] = struct{}{}
	used["10.42.0.2"] = struct{}{}
	p, err = AllocateIP(pool, used)
	if err != nil {
		t.Fatal(err)
	}
	if p.Addr().String() != "10.42.0.3" {
		t.Fatalf("second alloc: %s", p)
	}
}

func TestAllocateIPExhausted(t *testing.T) {
	pool := netip.MustParsePrefix("10.42.0.0/30")
	used := map[string]struct{}{"10.42.0.1": {}, "10.42.0.2": {}}
	if _, err := AllocateIP(pool, used); err == nil {
		t.Fatal("expected exhaustion")
	}
}

func TestParseCARejectsNonCA(t *testing.T) {
	caPEM, keyPEM, _, err := GenerateCA("c", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	hostPEM, hostKey, _, _, err := ca.SignHost("h", netip.MustParsePrefix("10.42.0.2/24"), nil, time.Hour, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCA(hostPEM, keyPEM); err == nil {
		t.Fatal("expected non-CA rejection")
	}
	if _, err := ParseCA(hostPEM, hostKey); err == nil {
		t.Fatal("expected signing-key rejection")
	}
}
