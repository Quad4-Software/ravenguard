// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

const defaultRingCapacity = 2000

var (
	defaultRingMu sync.Mutex
	defaultRing   *Ring
)

// DefaultRing returns the process-wide log ring created by Setup.
func DefaultRing() *Ring {
	defaultRingMu.Lock()
	defer defaultRingMu.Unlock()
	return defaultRing
}

// Setup configures the default slog logger and captures output into a ring buffer.
func Setup(level, format string) *slog.Logger {
	return SetupWithRing(level, format, nil)
}

// SetupWithRing configures slog with an optional ring. When ring is nil a
// capacity-2000 ring is created and stored as the default.
func SetupWithRing(level, format string, ring *Ring) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lv}
	var base slog.Handler
	out := io.Writer(os.Stderr)
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		base = slog.NewJSONHandler(out, opts)
	default:
		base = slog.NewTextHandler(out, opts)
	}

	if ring == nil {
		defaultRingMu.Lock()
		if defaultRing == nil {
			defaultRing = NewRing(defaultRingCapacity)
		}
		ring = defaultRing
		defaultRingMu.Unlock()
	} else {
		defaultRingMu.Lock()
		defaultRing = ring
		defaultRingMu.Unlock()
	}

	h := ring.Wrap(base)
	logger := slog.New(h)
	slog.SetDefault(logger)
	return logger
}
