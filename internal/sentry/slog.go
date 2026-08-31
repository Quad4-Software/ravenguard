// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package sentry

import (
	"context"
	"log/slog"

	sdk "github.com/getsentry/sentry-go"
)

// WrapHandler returns a slog.Handler that forwards error-level records to Sentry.
func WrapHandler(base slog.Handler, r *Reporter) slog.Handler {
	if r == nil || !r.enabled || base == nil {
		return base
	}
	return &slogBridge{next: base, r: r}
}

type slogBridge struct {
	next slog.Handler
	r    *Reporter
}

func (h *slogBridge) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *slogBridge) Handle(ctx context.Context, rec slog.Record) error {
	err := h.next.Handle(ctx, rec)
	if rec.Level >= slog.LevelError && h.r.enabled {
		h.forward(rec)
	}
	return err
}

func (h *slogBridge) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &slogBridge{next: h.next.WithAttrs(attrs), r: h.r}
}

func (h *slogBridge) WithGroup(name string) slog.Handler {
	return &slogBridge{next: h.next.WithGroup(name), r: h.r}
}

func (h *slogBridge) forward(rec slog.Record) {
	var caught error
	attrs := make(map[string]string, rec.NumAttrs())
	rec.Attrs(func(a slog.Attr) bool {
		if a.Key == "err" || a.Key == "error" {
			if e, ok := a.Value.Any().(error); ok {
				caught = e
			}
		}
		attrs[a.Key] = a.Value.String()
		return true
	})
	sdk.WithScope(func(scope *sdk.Scope) {
		scope.SetLevel(sdk.LevelError)
		scope.SetTag("logger", "slog")
		ctx := sdk.Context{"message": rec.Message}
		for k, v := range attrs {
			ctx[k] = v
		}
		scope.SetContext("slog", ctx)
		if caught != nil {
			sdk.CaptureException(caught)
			return
		}
		sdk.CaptureMessage(rec.Message)
	})
}
