// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package privacy_test

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/privacy"
)

func TestClientKeyStable(t *testing.T) {
	g := privacy.New(privacy.Config{
		HashClientIP: true,
		Secret:       []byte("hash-secret-16char"),
		LogIP:        "hash",
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

func TestClientKeyPlain(t *testing.T) {
	g := privacy.New(privacy.Config{
		HashClientIP: false,
		Secret:       []byte("hash-secret-16char"),
		LogIP:        "full",
	})
	if g.ClientKey("203.0.113.10") != "203.0.113.10" {
		t.Fatal("expected plain ip")
	}
	if g.LogIP("203.0.113.10") != "203.0.113.10" {
		t.Fatal("expected full log ip")
	}
}

func TestLogIPModes(t *testing.T) {
	g := privacy.New(privacy.Config{
		HashClientIP: true,
		Secret:       []byte("hash-secret-16char"),
		LogIP:        "off",
	})
	if g.LogIP("203.0.113.10") != "" {
		t.Fatal("expected empty log ip")
	}
}
