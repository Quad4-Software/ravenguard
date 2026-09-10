// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect_test

import (
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/detect"
)

func TestPenaltyTracker(t *testing.T) {
	pt := detect.NewPenaltyTracker(3, time.Minute)
	if pt.Exceeded("1.1.1.1") {
		t.Fatal("cold")
	}
	pt.Record("1.1.1.1", 404)
	pt.Record("1.1.1.1", 302)
	if pt.Exceeded("1.1.1.1") {
		t.Fatal("under threshold")
	}
	pt.Record("1.1.1.1", 200)
	pt.Record("1.1.1.1", 500)
	if !pt.Exceeded("1.1.1.1") {
		t.Fatal("expected exceeded")
	}
}

func TestPenaltyTrackerIgnoresCachedStatuses(t *testing.T) {
	pt := detect.NewPenaltyTracker(1, time.Minute)
	pt.Record("1.1.1.1", 200)
	pt.Record("1.1.1.1", 301)
	pt.Record("1.1.1.1", 404)
	pt.Record("1.1.1.1", 403)
	pt.Record("1.1.1.1", 429)
	if !pt.Exceeded("1.1.1.1") {
		t.Fatal("301 and 404 should count")
	}
}

func TestExpensiveStatus(t *testing.T) {
	cases := map[int]int{
		200: 0, 301: 1, 302: 1, 303: 1, 304: 0, 307: 1, 308: 1,
		400: 0, 401: 0, 403: 0, 404: 1, 410: 1, 429: 0,
		500: 1, 502: 1, 503: 1, 599: 1,
	}
	for status, want := range cases {
		if got := detect.ExpensiveStatus(status); got != want {
			t.Fatalf("ExpensiveStatus(%d)=%d want %d", status, got, want)
		}
	}
}
