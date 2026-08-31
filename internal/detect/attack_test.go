// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/detect"
)

func TestAttackTraversal(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/download?file=../../etc/passwd", nil)
	if got := detect.AttackMatch(r); got != "path_traversal" {
		t.Fatalf("got %q", got)
	}
}

func TestAttackNullByte(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/index.php%00.jpg", nil)
	if got := detect.AttackMatch(r); got != "null_byte" {
		t.Fatalf("got %q", got)
	}
}

func TestAttackSQLi(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/search?q=1'+union+select+1", nil)
	if got := detect.AttackMatch(r); got != "injection_probe" {
		t.Fatalf("got %q", got)
	}
}

func TestAttackClean(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/products/shoes?color=red", nil)
	if got := detect.AttackMatch(r); got != "" {
		t.Fatalf("got %q", got)
	}
}
