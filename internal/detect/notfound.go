// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect

import (
	"sync"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/strhash"
)

const statusShards = 64

type NotFoundTracker struct {
	threshold int
	window    time.Duration
	shards    [statusShards]nfShard
}

type nfShard struct {
	mu   sync.Mutex
	ents map[string]*nfEntry
}

type nfEntry struct {
	count int
	start time.Time
}

func NewNotFoundTracker(threshold int, window time.Duration) *NotFoundTracker {
	if threshold <= 0 {
		threshold = 20
	}
	if window <= 0 {
		window = time.Minute
	}
	t := &NotFoundTracker{threshold: threshold, window: window}
	for i := range t.shards {
		t.shards[i].ents = make(map[string]*nfEntry)
	}
	return t
}

func (t *NotFoundTracker) Exceeded(ip string) bool {
	if ip == "" {
		return false
	}
	s := &t.shards[strhash.String(ip)%statusShards]
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

func (t *NotFoundTracker) Record(ip string, status int) {
	if status != 404 || ip == "" {
		return
	}
	s := &t.shards[strhash.String(ip)%statusShards]
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.ents[ip]
	if !ok || now.Sub(e.start) > t.window {
		s.ents[ip] = &nfEntry{count: 1, start: now}
		return
	}
	e.count++
}

func (t *NotFoundTracker) Sweep(maxAge time.Duration) {
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
