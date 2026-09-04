// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/detect"
)

func BenchmarkScoreClean(b *testing.B) {
	cfg := detect.Config{
		MissingUAScore: 25, ScannerUAScore: 50, AIUAScore: 55,
		ProbePathScore: 40, OddMethodScore: 30, MissingAcceptScore: 10,
		MissingAcceptLangScore: 15, MissingSecFetchScore: 20,
		SecCHUAMismatchScore: 25, StarAcceptBrowserScore: 15,
		ForgeExpensiveScore: 40,
	}
	r := httptest.NewRequest(http.MethodGet, "/products/shoes", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Accept-Language", "en-US")
	r.Header.Set("Sec-Fetch-Site", "none")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	for range 100 {
		_ = detect.Score(r, cfg)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = detect.Score(r, cfg)
	}
}

func BenchmarkForgePathClass(b *testing.B) {
	paths := []string{
		"/owner/repo/compare/a...b",
		"/owner/repo/src/branch/main",
		"/owner/repo",
		"/owner/repo.git/info/refs",
		"/api/v1/repos/o/r/git/trees/abc",
		"/products/shoes",
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, p := range paths {
			_ = detect.ForgePathClass(p)
		}
	}
}

func BenchmarkAttackMatchClean(b *testing.B) {
	r := httptest.NewRequest(http.MethodGet, "/products/shoes?color=red", nil)
	b.ReportAllocs()
	for b.Loop() {
		_ = detect.AttackMatch(r)
	}
}

func BenchmarkAttackMatchProbe(b *testing.B) {
	r := httptest.NewRequest(http.MethodGet, "/search?q=1'+union+select+1", nil)
	b.ReportAllocs()
	for b.Loop() {
		_ = detect.AttackMatch(r)
	}
}
