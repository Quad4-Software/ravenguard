// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ratelimit_test

import (
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/ratelimit"
)

func TestAllowBurst(t *testing.T) {
	l := ratelimit.New(10, 3, time.Minute, false)
	if !l.Allow("1.1.1.1", "/") {
		t.Fatal("1")
	}
	if !l.Allow("1.1.1.1", "/") {
		t.Fatal("2")
	}
	if !l.Allow("1.1.1.1", "/") {
		t.Fatal("3")
	}
	if l.Allow("1.1.1.1", "/") {
		t.Fatal("expected deny")
	}
	if !l.Allow("2.2.2.2", "/") {
		t.Fatal("other ip")
	}
}

func TestPerPathFallsBackToClientBucket(t *testing.T) {
	// With per_path on, unique paths must still count against the client
	// aggregate. Cache-miss floods rotate through unique paths, so the client
	// bucket is the safety net.
	l := ratelimit.New(3, 3, time.Minute, true)
	if !l.Allow("1.1.1.1", "/a") {
		t.Fatal("first")
	}
	if !l.Allow("1.1.1.1", "/b") {
		t.Fatal("second")
	}
	if !l.Allow("1.1.1.1", "/c") {
		t.Fatal("third")
	}
	if l.Allow("1.1.1.1", "/d") {
		t.Fatal("expected deny after client bucket exhausted")
	}
	if l.Allow("1.1.1.1", "/a") {
		t.Fatal("expected deny on an existing path too")
	}
}
