// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

func Setup(level, format string) *slog.Logger {
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
	var h slog.Handler
	out := io.Writer(os.Stderr)
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		h = slog.NewJSONHandler(out, opts)
	default:
		h = slog.NewTextHandler(out, opts)
	}
	logger := slog.New(h)
	slog.SetDefault(logger)
	return logger
}
