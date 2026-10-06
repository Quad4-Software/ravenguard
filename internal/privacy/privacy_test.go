// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package privacy_test

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/privacy"
)

func TestClientKeyStable(t *testing.T) {
	g := privacy.New(privacy.Config{
		Secret: []byte("hash-secret-16char"),
		LogIP:  "hash",
	})
	a := g.ClientKey("203.0.113.10")
	b := g.ClientKey("203.0.113.10")
	if a == "" || a != b {
		t.Fatalf("unstable hash %q %q", a, b)
	}
	if a == "203.0.113.10" {
		t.Fatal("expected hashed key")
	}
	if g.ClientKey("203.0.113.11") == a {
		t.Fatal("different IPs should differ")
	}
}

func TestClientKeyAlwaysHashed(t *testing.T) {
	g := privacy.New(privacy.Config{
		Secret: []byte("hash-secret-16char"),
		LogIP:  "hash",
	})
	key := g.ClientKey("203.0.113.10")
	if key == "" || key == "203.0.113.10" {
		t.Fatal("client key must always be hashed")
	}
	if g.LogIP("203.0.113.10") == "203.0.113.10" {
		t.Fatal("log ip must never be raw")
	}
}

func TestLogIPModes(t *testing.T) {
	g := privacy.New(privacy.Config{
		Secret: []byte("hash-secret-16char"),
		LogIP:  "off",
	})
	if g.LogIP("203.0.113.10") != "" {
		t.Fatal("expected empty log ip")
	}
}
