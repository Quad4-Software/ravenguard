// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package requestlog

import (
	"encoding/json"
	"sync"
	"time"
)

const (
	ActionBlock     = "block"
	ActionChallenge = "challenge"
	ActionRateLimit = "ratelimit"
	ActionCoraza    = "coraza"
	ActionOpenAPI   = "openapi"
	ActionAccess    = "access"
)

// Event is one WAF deny (or challenge) outcome keyed by Ray ID.
type Event struct {
	Ray       string            `json:"ray"`
	Action    string            `json:"action"`
	Reason    string            `json:"reason"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Host      string            `json:"host"`
	UA        string            `json:"ua"`
	IPHash    string            `json:"ip_hash"`
	BindID    string            `json:"bind_id"`
	Score     int               `json:"score"`
	Details   map[string]string `json:"details,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// Persister stores events durably (optional).
type Persister interface {
	InsertWAFEvent(e Event) error
	GetWAFEventByRay(ray string) (Event, bool, error)
	ListWAFEvents(limit int) ([]Event, error)
	PurgeWAFEventsOlderThan(cutoff time.Time) (int64, error)
}

// Logger keeps a hot in-memory index and optional SQLite dual-write.
type Logger struct {
	mu      sync.RWMutex
	byRay   map[string]Event
	order   []string
	maxHot  int
	persist Persister
}

// New creates a logger with a bounded hot index.
func New(hotCapacity int) *Logger {
	if hotCapacity < 1 {
		hotCapacity = 2000
	}
	return &Logger{
		byRay:  make(map[string]Event, hotCapacity),
		order:  make([]string, 0, hotCapacity),
		maxHot: hotCapacity,
	}
}

// SetPersister attaches durable storage.
func (l *Logger) SetPersister(p Persister) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.persist = p
	l.mu.Unlock()
}

// Record stores a deny event. Empty ray is ignored.
func (l *Logger) Record(e Event) {
	if l == nil || e.Ray == "" {
		return
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	if e.Details == nil {
		e.Details = map[string]string{}
	}
	l.mu.Lock()
	if prev, ok := l.byRay[e.Ray]; ok && prev.BindID != "" && e.BindID != "" && prev.BindID != e.BindID {
		l.mu.Unlock()
		return
	}
	if _, ok := l.byRay[e.Ray]; !ok {
		if len(l.order) >= l.maxHot {
			old := l.order[0]
			l.order = l.order[1:]
			delete(l.byRay, old)
		}
		l.order = append(l.order, e.Ray)
	}
	l.byRay[e.Ray] = e
	p := l.persist
	l.mu.Unlock()
	if p != nil {
		_ = p.InsertWAFEvent(e)
	}
}

// GetByRay returns the newest matching event from hot index or persister.
func (l *Logger) GetByRay(ray string) (Event, bool) {
	if l == nil || ray == "" {
		return Event{}, false
	}
	l.mu.RLock()
	e, ok := l.byRay[ray]
	p := l.persist
	l.mu.RUnlock()
	if ok {
		return e, true
	}
	if p == nil {
		return Event{}, false
	}
	ev, found, err := p.GetWAFEventByRay(ray)
	if err != nil || !found {
		return Event{}, false
	}
	return ev, true
}

// Recent returns up to limit newest events from the hot index.
func (l *Logger) Recent(limit int) []Event {
	if l == nil {
		return nil
	}
	if limit <= 0 {
		limit = 50
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	n := len(l.order)
	if n == 0 {
		return nil
	}
	out := make([]Event, 0, limit)
	for i := n - 1; i >= 0 && len(out) < limit; i-- {
		if e, ok := l.byRay[l.order[i]]; ok {
			out = append(out, e)
		}
	}
	return out
}

// RecentPreferDB returns recent events, preferring durable store when present.
func (l *Logger) RecentPreferDB(limit int) []Event {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	p := l.persist
	l.mu.RUnlock()
	if p != nil {
		if rows, err := p.ListWAFEvents(limit); err == nil && len(rows) > 0 {
			return rows
		}
	}
	return l.Recent(limit)
}

// PurgeOlderThan removes durable rows older than cutoff.
func (l *Logger) PurgeOlderThan(cutoff time.Time) {
	if l == nil {
		return
	}
	l.mu.RLock()
	p := l.persist
	l.mu.RUnlock()
	if p != nil {
		_, _ = p.PurgeWAFEventsOlderThan(cutoff)
	}
}

// DetailsJSON marshals details for SQL storage.
func DetailsJSON(d map[string]string) string {
	if len(d) == 0 {
		return "{}"
	}
	b, err := json.Marshal(d)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ParseDetailsJSON unmarshals details from SQL.
func ParseDetailsJSON(s string) map[string]string {
	if s == "" || s == "{}" {
		return map[string]string{}
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return map[string]string{}
	}
	return m
}
