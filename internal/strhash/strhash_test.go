// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package strhash_test

import (
	"hash/fnv"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/strhash"
)

func TestStringMatchesFNV(t *testing.T) {
	cases := []string{"", "a", "1.2.3.4", "hello|world", "Mozilla/5.0"}
	for _, s := range cases {
		h := fnv.New32a()
		_, _ = h.Write([]byte(s))
		want := h.Sum32()
		if got := strhash.String(s); got != want {
			t.Fatalf("%q: got %d want %d", s, got, want)
		}
	}
}

func BenchmarkString(b *testing.B) {
	s := "203.0.113.50|/api/v1/items"
	b.ReportAllocs()
	for b.Loop() {
		_ = strhash.String(s)
	}
}
