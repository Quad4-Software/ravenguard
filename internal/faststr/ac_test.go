// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package faststr_test

import (
	"strings"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/faststr"
)

func TestMatcherContains(t *testing.T) {
	m := faststr.NewMatcher([]string{"sqlmap", "nikto", "chrome/"})
	ua := strings.ToLower("Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36")
	if !m.ContainsString(ua) {
		t.Fatal("expected chrome match")
	}
	if m.ContainsString(strings.ToLower("Mozilla/5.0 (compatible)")) {
		t.Fatal("unexpected match")
	}
	if !m.Contains([]byte("x-sqlmap-y")) {
		t.Fatal("expected sqlmap match")
	}
}

func FuzzMatcherContains(f *testing.F) {
	m := faststr.NewMatcher([]string{"sqlmap", "nikto", "curl/", "python-requests"})
	f.Add("Mozilla/5.0")
	f.Add("sqlmap/1.0")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		_ = m.ContainsString(strings.ToLower(s))
		_ = faststr.ContainsFold(s, "sqlmap")
		_ = faststr.ContainsBytes([]byte(strings.ToLower(s)), "nikto")
	})
}

func BenchmarkMatcherContains(b *testing.B) {
	m := faststr.NewMatcher([]string{
		"sqlmap", "nikto", "nmap", "masscan", "gobuster", "wfuzz", "nuclei",
		"python-requests", "go-http-client", "curl/", "wget/", "scrapy",
	})
	ua := []byte(strings.ToLower("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"))
	b.ReportAllocs()
	for b.Loop() {
		_ = m.Contains(ua)
	}
}
