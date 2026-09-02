// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package logging

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Entry is one captured log record for the admin UI.
type Entry struct {
	Time    time.Time         `json:"time"`
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Attrs   map[string]string `json:"attrs,omitempty"`
}

// Ring is a thread-safe circular buffer of log entries.
type Ring struct {
	mu   sync.RWMutex
	buf  []Entry
	cap  int
	next int
	full bool
}

// NewRing creates a ring with the given capacity (minimum 1).
func NewRing(capacity int) *Ring {
	if capacity < 1 {
		capacity = 1
	}
	return &Ring{
		buf: make([]Entry, capacity),
		cap: capacity,
	}
}

// Handler returns an slog.Handler that records into the ring at or above level.
func (r *Ring) Handler(level slog.Level) slog.Handler {
	return &ringHandler{ring: r, level: level}
}

// Wrap returns an slog.Handler that fans out to the ring and inner.
func (r *Ring) Wrap(inner slog.Handler) slog.Handler {
	level := slog.LevelDebug
	if inner != nil {
		// Match the inner handler's effective floor when possible.
		for _, lv := range []slog.Level{slog.LevelError, slog.LevelWarn, slog.LevelInfo, slog.LevelDebug} {
			if inner.Enabled(context.Background(), lv) {
				level = lv
			}
		}
	}
	return &ringHandler{ring: r, level: level, inner: inner}
}

// Snapshot returns up to limit entries at or above minLevel, newest first.
// A non-positive limit returns all matching entries.
func (r *Ring) Snapshot(limit int, minLevel string) []Entry {
	minLvl := parseLevel(minLevel)
	r.mu.RLock()
	defer r.mu.RUnlock()

	n := r.cap
	if !r.full {
		n = r.next
	}
	out := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		idx := r.next - 1 - i
		if idx < 0 {
			idx += r.cap
		}
		e := r.buf[idx]
		if parseLevel(e.Level) < minLvl {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func (r *Ring) record(e Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = e
	r.next = (r.next + 1) % r.cap
	if r.next == 0 {
		r.full = true
	}
}

type ringHandler struct {
	ring   *Ring
	level  slog.Level
	inner  slog.Handler
	attrs  []slog.Attr
	groups []string
}

func (h *ringHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if h.inner != nil && h.inner.Enabled(ctx, level) {
		return true
	}
	return level >= h.level
}

func (h *ringHandler) Handle(ctx context.Context, rec slog.Record) error {
	var err error
	if h.inner != nil && h.inner.Enabled(ctx, rec.Level) {
		err = h.inner.Handle(ctx, rec)
	}
	if rec.Level < h.level {
		return err
	}
	attrs := make(map[string]string)
	prefix := strings.Join(h.groups, ".")
	for _, a := range h.attrs {
		appendAttr(attrs, prefix, a)
	}
	rec.Attrs(func(a slog.Attr) bool {
		appendAttr(attrs, prefix, a)
		return true
	})
	e := Entry{
		Time:    rec.Time,
		Level:   rec.Level.String(),
		Message: rec.Message,
	}
	if len(attrs) > 0 {
		e.Attrs = attrs
	}
	h.ring.record(e)
	return err
}

func (h *ringHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := *h
	nh.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	if h.inner != nil {
		nh.inner = h.inner.WithAttrs(attrs)
	}
	return &nh
}

func (h *ringHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	nh := *h
	nh.groups = append(append([]string{}, h.groups...), name)
	if h.inner != nil {
		nh.inner = h.inner.WithGroup(name)
	}
	return &nh
}

func appendAttr(dst map[string]string, prefix string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	key := a.Key
	if prefix != "" {
		key = prefix + "." + a.Key
	}
	switch a.Value.Kind() {
	case slog.KindGroup:
		for _, ga := range a.Value.Group() {
			appendAttr(dst, key, ga)
		}
	default:
		if a.Key == "" {
			return
		}
		dst[key] = a.Value.String()
	}
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
