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
