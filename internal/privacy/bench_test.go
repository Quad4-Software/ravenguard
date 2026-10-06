// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package privacy_test

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/privacy"
)

func BenchmarkClientKeyHash(b *testing.B) {
	g := privacy.New(privacy.Config{
		Secret: []byte("bench-secret"),
		LogIP:  "hash",
	})
	b.ReportAllocs()
	for b.Loop() {
		_ = g.ClientKey("203.0.113.50")
	}
}
