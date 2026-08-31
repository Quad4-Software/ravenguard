// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package rayid_test

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/rayid"
)

func BenchmarkNew(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = rayid.New()
	}
}
