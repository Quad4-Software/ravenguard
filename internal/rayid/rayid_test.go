// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package rayid_test

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/rayid"
)

func TestNewUnique(t *testing.T) {
	a := rayid.New()
	b := rayid.New()
	if a == "" || b == "" || a == b {
		t.Fatalf("a=%q b=%q", a, b)
	}
}
