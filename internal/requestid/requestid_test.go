// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package requestid_test

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/requestid"
)

func TestNewUnique(t *testing.T) {
	a := requestid.New()
	b := requestid.New()
	if a == "" || b == "" || a == b {
		t.Fatalf("a=%q b=%q", a, b)
	}
}
