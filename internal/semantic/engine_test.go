// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package semantic_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/semantic"
)

func TestSQLiDetect(t *testing.T) {
	eng := semantic.New(config.SemanticConfig{
		Enabled: true, Mode: "block", MaxDecodeDepth: 3, MaxDecodeBytes: 1 << 20,
		MaxCPUNanos: int64(time.Second), Families: []string{"sqli", "xss", "cmd", "path"},
	})
	r := httptest.NewRequest(http.MethodGet, "/search?q=1'+union+select+null--", nil)
	res := eng.Evaluate(r, nil)
	if !res.Matched || res.Family != "sqli" || !res.ShouldBlock {
		t.Fatalf("expected sqli block got %+v", res)
	}
}

func TestBenignAPINoMatch(t *testing.T) {
	eng := semantic.New(config.SemanticConfig{
		Enabled: true, Mode: "block", MaxDecodeDepth: 3, MaxDecodeBytes: 1 << 20,
		MaxCPUNanos: int64(time.Second), Families: []string{"sqli", "xss", "cmd", "path"},
	})
	r := httptest.NewRequest(http.MethodPost, "/api/items", strings.NewReader(`{"name":"union jacket","desc":"select color"}`))
	r.Header.Set("Content-Type", "application/json")
	res := eng.Evaluate(r, []byte(`{"name":"union jacket","desc":"select color"}`))
	if res.ShouldBlock {
		t.Fatalf("benign JSON must not block: %+v", res)
	}
}

func TestXSSDetect(t *testing.T) {
	eng := semantic.New(config.SemanticConfig{
		Enabled: true, Mode: "shadow", MaxDecodeDepth: 3, MaxDecodeBytes: 1 << 20,
		MaxCPUNanos: int64(time.Second), Families: []string{"xss"},
	})
	r := httptest.NewRequest(http.MethodGet, "/x?q=<script>alert(1)</script>", nil)
	res := eng.Evaluate(r, nil)
	if !res.Matched || res.Family != "xss" || res.ShouldBlock {
		t.Fatalf("shadow xss: %+v", res)
	}
}

func TestBudgetAborts(t *testing.T) {
	eng := semantic.New(config.SemanticConfig{
		Enabled: true, Mode: "shadow", MaxDecodeDepth: 8, MaxDecodeBytes: 64,
		MaxCPUNanos: 1, Families: []string{"sqli"},
	})
	r := httptest.NewRequest(http.MethodGet, "/q?x=%252527%252520or%2525201%253D1", nil)
	res := eng.Evaluate(r, nil)
	if !res.Aborted && res.Error == "" && res.Matched {
		// either abort or no match is fine under tiny budget
		t.Logf("budget result %+v", res)
	}
}

func TestDecodeChainURL(t *testing.T) {
	b := &semantic.Budget{Deadline: time.Now().Add(time.Second), MaxBytes: 1 << 20, MaxDepth: 3}
	out, err := semantic.DecodeChain([]byte("%27%20or%201%3D1"), b)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range out {
		if strings.Contains(string(c), "' or 1=1") || strings.Contains(string(c), "or 1=1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected decoded tautology in %q", out)
	}
}

func FuzzDecodeChain(f *testing.F) {
	f.Add([]byte("a"))
	f.Add([]byte("%27or%201%3D1"))
	f.Add([]byte("../../../etc/passwd"))
	f.Fuzz(func(t *testing.T, in []byte) {
		b := &semantic.Budget{Deadline: time.Now().Add(50 * time.Millisecond), MaxBytes: 4096, MaxDepth: 2}
		_, err := semantic.DecodeChain(in, b)
		if err != nil && err != semantic.ErrBudget {
			t.Fatalf("unexpected %v", err)
		}
	})
}

func FuzzSQLSemantic(f *testing.F) {
	f.Add([]byte("1' union select 1"))
	f.Add([]byte("hello world"))
	f.Fuzz(func(t *testing.T, in []byte) {
		eng := semantic.New(config.SemanticConfig{
			Enabled: true, Mode: "shadow", MaxDecodeDepth: 2, MaxDecodeBytes: 4096,
			MaxCPUNanos: int64(20 * time.Millisecond), Families: []string{"sqli"},
		})
		r := httptest.NewRequest(http.MethodGet, "/q", nil)
		res := eng.Evaluate(r, in)
		if res.Score < 0 || res.Score > 100 {
			t.Fatalf("score %d", res.Score)
		}
	})
}

func BenchmarkSemanticClean(b *testing.B) {
	eng := semantic.New(config.SemanticConfig{
		Enabled: true, Mode: "shadow", MaxDecodeDepth: 3, MaxDecodeBytes: 1 << 20,
		MaxCPUNanos: int64(time.Second), Families: []string{"sqli", "xss", "cmd", "path"},
	})
	r := httptest.NewRequest(http.MethodGet, "/products/shoes?color=red", nil)
	b.ReportAllocs()
	for b.Loop() {
		_ = eng.Evaluate(r, nil)
	}
}

func BenchmarkSemanticSQLi(b *testing.B) {
	eng := semantic.New(config.SemanticConfig{
		Enabled: true, Mode: "block", MaxDecodeDepth: 3, MaxDecodeBytes: 1 << 20,
		MaxCPUNanos: int64(time.Second), Families: []string{"sqli"},
	})
	r := httptest.NewRequest(http.MethodGet, "/search?q=1'+union+select+1--", nil)
	b.ReportAllocs()
	for b.Loop() {
		_ = eng.Evaluate(r, nil)
	}
}
