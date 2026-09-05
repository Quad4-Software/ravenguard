// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package requestlog

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ActionBlock     = "block"
	ActionChallenge = "challenge"
	ActionRateLimit = "ratelimit"
	ActionCoraza    = "coraza"
	ActionOpenAPI   = "openapi"
	ActionAccess    = "access"
	ActionSemantic  = "semantic"
	ActionML        = "ml"
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

// Counters are WAF outcome tallies for stats and admin views.
type Counters struct {
	Challenges uint64 `json:"challenges"`
	Blocks     uint64 `json:"blocks"`
	RateLimits uint64 `json:"ratelimits"`
	Coraza     uint64 `json:"coraza"`
	Access     uint64 `json:"access"`
	OpenAPI    uint64 `json:"openapi"`
	Semantic   uint64 `json:"semantic"`
	ML         uint64 `json:"ml"`
}

// Sum returns the total of all action counters.
func (c Counters) Sum() uint64 {
	return c.Challenges + c.Blocks + c.RateLimits + c.Coraza + c.Access + c.OpenAPI + c.Semantic + c.ML
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
	head    int
	len     int
	maxHot  int
	persist Persister

	challenges atomic.Uint64
	blocks     atomic.Uint64
	ratelimits atomic.Uint64
	coraza     atomic.Uint64
	access     atomic.Uint64
	openapi    atomic.Uint64
	semantic   atomic.Uint64
	ml         atomic.Uint64

	ivChallenges atomic.Uint64
	ivBlocks     atomic.Uint64
	ivRatelimits atomic.Uint64
	ivCoraza     atomic.Uint64
	ivAccess     atomic.Uint64
	ivOpenAPI    atomic.Uint64
	ivSemantic   atomic.Uint64
	ivML         atomic.Uint64
}

// New creates a logger with a bounded hot index.
func New(hotCapacity int) *Logger {
	if hotCapacity < 1 {
		hotCapacity = 2000
	}
	return &Logger{
		byRay:  make(map[string]Event, hotCapacity),
		order:  make([]string, hotCapacity),
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
		if l.len >= l.maxHot {
			old := l.order[l.head]
			delete(l.byRay, old)
			l.order[l.head] = e.Ray
			l.head = (l.head + 1) % l.maxHot
		} else {
			idx := (l.head + l.len) % l.maxHot
			l.order[idx] = e.Ray
			l.len++
		}
	}
	l.byRay[e.Ray] = e
	p := l.persist
	l.mu.Unlock()
	l.bump(e.Action)
	if p != nil {
		_ = p.InsertWAFEvent(e)
	}
}

func (l *Logger) bump(action string) {
	if l == nil {
		return
	}
	switch action {
	case ActionChallenge:
		l.challenges.Add(1)
		l.ivChallenges.Add(1)
	case ActionBlock:
		l.blocks.Add(1)
		l.ivBlocks.Add(1)
	case ActionRateLimit:
		l.ratelimits.Add(1)
		l.ivRatelimits.Add(1)
	case ActionCoraza:
		l.coraza.Add(1)
		l.ivCoraza.Add(1)
	case ActionAccess:
		l.access.Add(1)
		l.ivAccess.Add(1)
	case ActionOpenAPI:
		l.openapi.Add(1)
		l.ivOpenAPI.Add(1)
	case ActionSemantic:
		l.semantic.Add(1)
		l.ivSemantic.Add(1)
	case ActionML:
		l.ml.Add(1)
		l.ivML.Add(1)
	}
}

// Totals returns lifetime WAF outcome counts since process start.
func (l *Logger) Totals() Counters {
	if l == nil {
		return Counters{}
	}
	return Counters{
		Challenges: l.challenges.Load(),
		Blocks:     l.blocks.Load(),
		RateLimits: l.ratelimits.Load(),
		Coraza:     l.coraza.Load(),
		Access:     l.access.Load(),
		OpenAPI:    l.openapi.Load(),
		Semantic:   l.semantic.Load(),
		ML:         l.ml.Load(),
	}
}

// TakeInterval returns and clears per-interval counters for stats logging.
func (l *Logger) TakeInterval() Counters {
	if l == nil {
		return Counters{}
	}
	return Counters{
		Challenges: l.ivChallenges.Swap(0),
		Blocks:     l.ivBlocks.Swap(0),
		RateLimits: l.ivRatelimits.Swap(0),
		Coraza:     l.ivCoraza.Swap(0),
		Access:     l.ivAccess.Swap(0),
		OpenAPI:    l.ivOpenAPI.Swap(0),
		Semantic:   l.ivSemantic.Swap(0),
		ML:         l.ivML.Swap(0),
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
	if l.len == 0 {
		return nil
	}
	out := make([]Event, 0, limit)
	for i := 0; i < l.len && len(out) < limit; i++ {
		idx := (l.head + l.len - 1 - i) % l.maxHot
		ray := l.order[idx]
		if e, ok := l.byRay[ray]; ok {
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
