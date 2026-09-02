// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package logging

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

func TestRingSnapshotNewestFirst(t *testing.T) {
	ring := NewRing(10)
	h := ring.Handler(slog.LevelDebug)
	logger := slog.New(h)

	logger.Info("first", "n", 1)
	time.Sleep(2 * time.Millisecond)
	logger.Warn("second", "n", 2)
	logger.Error("third", "n", 3)

	all := ring.Snapshot(0, "debug")
	if len(all) != 3 {
		t.Fatalf("got %d entries, want 3", len(all))
	}
	if all[0].Message != "third" || all[1].Message != "second" || all[2].Message != "first" {
		t.Fatalf("order = %#v", []string{all[0].Message, all[1].Message, all[2].Message})
	}

	limited := ring.Snapshot(2, "info")
	if len(limited) != 2 {
		t.Fatalf("limit: got %d", len(limited))
	}
	if limited[0].Message != "third" {
		t.Fatalf("expected newest first, got %q", limited[0].Message)
	}

	warnOnly := ring.Snapshot(0, "warn")
	if len(warnOnly) != 2 {
		t.Fatalf("warn filter: got %d %#v", len(warnOnly), warnOnly)
	}
}

func TestRingWrapFansOut(t *testing.T) {
	ring := NewRing(8)
	var captured []string
	inner := slog.NewJSONHandler(&captureWriter{fn: func(p []byte) {
		captured = append(captured, string(p))
	}}, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(ring.Wrap(inner))
	logger.Info("hello", "k", "v")
	if len(captured) == 0 {
		t.Fatal("expected inner handler output")
	}
	snap := ring.Snapshot(1, "info")
	if len(snap) != 1 || snap[0].Message != "hello" {
		t.Fatalf("ring snap = %#v", snap)
	}
	if snap[0].Attrs["k"] != "v" {
		t.Fatalf("attrs = %#v", snap[0].Attrs)
	}
	_ = context.Background()
}

type captureWriter struct {
	fn func([]byte)
}

func (c *captureWriter) Write(p []byte) (int, error) {
	c.fn(append([]byte(nil), p...))
	return len(p), nil
}
