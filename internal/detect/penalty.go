// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect

import (
	"sync"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/strhash"
)

const penaltyShards = 64

// PenaltyTracker counts expensive upstream responses per client: cache-miss
// statuses such as redirects, missing pages, and 5xx errors. Attackers probe
// for non-cacheable paths and hammer them; clients that accumulate too many
// expensive responses get challenged or blocked by the caller.
type PenaltyTracker struct {
	threshold int
	window    time.Duration
	shards    [penaltyShards]penShard
}

type penShard struct {
	mu   sync.Mutex
	ents map[string]*penEntry
}

type penEntry struct {
	count int
	start time.Time
}

func NewPenaltyTracker(threshold int, window time.Duration) *PenaltyTracker {
	if threshold <= 0 {
		threshold = 30
	}
	if window <= 0 {
		window = time.Minute
	}
	t := &PenaltyTracker{threshold: threshold, window: window}
	for i := range t.shards {
		t.shards[i].ents = make(map[string]*penEntry)
	}
	return t
}

// ExpensiveStatus reports whether an upstream status is a cache-miss class
// that attackers can weaponize. Redirects and missing pages are the classic
// cache-bypass surfaces; 5xx reflects upstream work that is not a normal hit.
func ExpensiveStatus(status int) int {
	switch {
	case status == 404 || status == 410:
		return 1
	case status == 301 || status == 302 || status == 303 || status == 307 || status == 308:
		return 1
	case status >= 500 && status <= 599:
		return 1
	}
	return 0
}

// CacheableMissStatus reports whether an upstream status is a cache-miss
// class that is safe to cache briefly. Redirects and missing pages are the
// classic cache-bypass surfaces. 5xx and other errors are not included because
// caching an error page can mask transient upstream recovery.
func CacheableMissStatus(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308, 404, 410:
		return true
	}
	return false
}

func (t *PenaltyTracker) Exceeded(ip string) bool {
	if ip == "" {
		return false
	}
	s := &t.shards[strhash.String(ip)%penaltyShards]
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.ents[ip]
	if !ok {
		return false
	}
	if now.Sub(e.start) > t.window {
		delete(s.ents, ip)
		return false
	}
	return e.count >= t.threshold
}

func (t *PenaltyTracker) Record(ip string, status int) {
	if ExpensiveStatus(status) == 0 || ip == "" {
		return
	}
	s := &t.shards[strhash.String(ip)%penaltyShards]
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.ents[ip]
	if !ok || now.Sub(e.start) > t.window {
		s.ents[ip] = &penEntry{count: 1, start: now}
		return
	}
	e.count++
}

func (t *PenaltyTracker) Sweep(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for k, e := range s.ents {
			if e.start.Before(cutoff) {
				delete(s.ents, k)
			}
		}
		s.mu.Unlock()
	}
}
