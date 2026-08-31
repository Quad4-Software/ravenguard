// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect_test

import (
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/detect"
)

func TestNotFoundTracker(t *testing.T) {
	nf := detect.NewNotFoundTracker(3, time.Minute)
	if nf.Exceeded("1.1.1.1") {
		t.Fatal("cold")
	}
	nf.Record("1.1.1.1", 404)
	nf.Record("1.1.1.1", 404)
	if nf.Exceeded("1.1.1.1") {
		t.Fatal("under threshold")
	}
	nf.Record("1.1.1.1", 200)
	nf.Record("1.1.1.1", 404)
	if !nf.Exceeded("1.1.1.1") {
		t.Fatal("expected exceeded")
	}
}
