// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package faststr_test

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/faststr"
)

func TestContainsFold(t *testing.T) {
	if !faststr.ContainsFold("Mozilla/5.0 SQLMAP/1", "sqlmap") {
		t.Fatal("expected match")
	}
	if faststr.ContainsFold("Mozilla/5.0", "sqlmap") {
		t.Fatal("unexpected")
	}
}

func BenchmarkContainsFold(b *testing.B) {
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	b.ReportAllocs()
	for b.Loop() {
		_ = faststr.ContainsFold(ua, "sqlmap")
		_ = faststr.ContainsFold(ua, "chrome/")
	}
}
