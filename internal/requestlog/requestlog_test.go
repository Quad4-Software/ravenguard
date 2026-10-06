// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package requestlog

import (
	"testing"
	"time"
)

func TestLoggerHotIndex(t *testing.T) {
	l := New(2)
	l.Record(Event{RequestID: "a", Action: ActionBlock, Reason: "one"})
	l.Record(Event{RequestID: "b", Action: ActionBlock, Reason: "two"})
	l.Record(Event{RequestID: "c", Action: ActionBlock, Reason: "three"})
	if _, ok := l.GetByID("a"); ok {
		t.Fatal("expected a evicted")
	}
	if e, ok := l.GetByID("c"); !ok || e.Reason != "three" {
		t.Fatalf("missing c: %+v ok=%v", e, ok)
	}
	recent := l.Recent(10)
	if len(recent) != 2 {
		t.Fatalf("recent len=%d", len(recent))
	}
	if recent[0].RequestID != "c" {
		t.Fatalf("newest first got %s", recent[0].RequestID)
	}
}

func TestLoggerOverwriteSameRequestID(t *testing.T) {
	l := New(10)
	l.Record(Event{RequestID: "r1", Action: ActionChallenge, Reason: "first"})
	l.Record(Event{RequestID: "r1", Action: ActionBlock, Reason: "second", CreatedAt: time.Now().UTC()})
	e, ok := l.GetByID("r1")
	if !ok || e.Action != ActionBlock || e.Reason != "second" {
		t.Fatalf("got %+v", e)
	}
}

func TestLoggerRejectForeignBindOverwrite(t *testing.T) {
	l := New(10)
	l.Record(Event{RequestID: "r1", Action: ActionBlock, Reason: "victim", BindID: "bind-a"})
	l.Record(Event{RequestID: "r1", Action: ActionChallenge, Reason: "spoof", BindID: "bind-b"})
	e, ok := l.GetByID("r1")
	if !ok || e.Reason != "victim" || e.BindID != "bind-a" {
		t.Fatalf("spoof overwrote event: %+v", e)
	}
	l.Record(Event{RequestID: "r1", Action: ActionChallenge, Reason: "same", BindID: "bind-a"})
	e, ok = l.GetByID("r1")
	if !ok || e.Reason != "same" {
		t.Fatalf("same bind should update: %+v", e)
	}
}

func TestLoggerCounters(t *testing.T) {
	l := New(10)
	l.Record(Event{RequestID: "a", Action: ActionChallenge, BindID: "x"})
	l.Record(Event{RequestID: "b", Action: ActionBlock})
	l.Record(Event{RequestID: "c", Action: ActionRateLimit})
	l.Record(Event{RequestID: "d", Action: ActionChallenge})
	// Foreign bind must not overwrite or bump.
	l.Record(Event{RequestID: "a", Action: ActionBlock, BindID: "y"})

	got := l.Totals()
	if got.Challenges != 2 || got.Blocks != 1 || got.RateLimits != 1 {
		t.Fatalf("totals=%+v", got)
	}
	iv := l.TakeInterval()
	if iv.Challenges != 2 || iv.Blocks != 1 || iv.RateLimits != 1 {
		t.Fatalf("interval=%+v", iv)
	}
	iv2 := l.TakeInterval()
	if iv2.Sum() != 0 {
		t.Fatalf("interval should clear: %+v", iv2)
	}
	if l.Totals().Challenges != 2 {
		t.Fatalf("totals should keep: %+v", l.Totals())
	}
}
