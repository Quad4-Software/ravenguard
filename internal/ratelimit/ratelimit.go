// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ratelimit

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/strhash"
)

const shards = 256

type liveCfg struct {
	rate    float64
	burstF  float64
	perPath bool
}

type Limiter struct {
	requests int
	burst    int
	window   time.Duration
	live     atomic.Pointer[liveCfg]
	shards   [shards]shard
}

type shard struct {
	mu   sync.Mutex
	ents map[string]*clientBucket
}

type clientBucket struct {
	tokens float64
	last   time.Time
	paths  map[string]*entry
}

type entry struct {
	tokens float64
	last   time.Time
}

var entryPool = sync.Pool{
	New: func() any {
		return &entry{}
	},
}

var bucketPool = sync.Pool{
	New: func() any {
		return &clientBucket{}
	},
}

func New(requests, burst int, window time.Duration, perPath bool) *Limiter {
	if burst <= 0 {
		burst = requests
	}
	if window <= 0 {
		window = time.Minute
	}
	l := &Limiter{
		requests: requests,
		burst:    burst,
		window:   window,
	}
	cfg := &liveCfg{
		rate:    float64(requests) / window.Seconds(),
		burstF:  float64(burst),
		perPath: perPath,
	}
	l.live.Store(cfg)
	for i := range l.shards {
		l.shards[i].ents = make(map[string]*clientBucket)
	}
	return l
}

func (l *Limiter) Allow(ip, path string) bool {
	return l.AllowN(ip, path, 1)
}

func (l *Limiter) AllowN(ip, path string, cost int) bool {
	if cost <= 0 {
		cost = 1
	}
	cfg := l.live.Load()
	if cfg == nil {
		return true
	}
	s := &l.shards[strhash.String(ip)%shards]
	now := time.Now()
	need := float64(cost)

	s.mu.Lock()
	b, ok := s.ents[ip]
	if !ok {
		b = bucketPool.Get().(*clientBucket)
		b.tokens = cfg.burstF
		b.last = now
		if b.paths != nil {
			clear(b.paths)
		}
		s.ents[ip] = b
	}

	if !cfg.perPath {
		ok = refillAllow(&b.tokens, &b.last, now, cfg.rate, cfg.burstF, need)
		s.mu.Unlock()
		return ok
	}

	if path == "" {
		path = "/"
	}
	if b.paths == nil {
		b.paths = make(map[string]*entry)
	}
	e, ok := b.paths[path]
	if !ok {
		e = entryPool.Get().(*entry)
		e.tokens = cfg.burstF
		e.last = now
		b.paths[path] = e
	}
	ok = refillAllow(&e.tokens, &e.last, now, cfg.rate, cfg.burstF, need)
	s.mu.Unlock()
	return ok
}

func refillAllow(tokens *float64, last *time.Time, now time.Time, rate, burst, need float64) bool {
	elapsed := now.Sub(*last).Seconds()
	*last = now
	*tokens += elapsed * rate
	if *tokens > burst {
		*tokens = burst
	}
	if *tokens < need {
		return false
	}
	*tokens -= need
	return true
}

func (l *Limiter) Sweep(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	cfg := l.live.Load()
	perPath := cfg != nil && cfg.perPath
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		for k, b := range s.ents {
			if perPath && b.paths != nil {
				for pk, e := range b.paths {
					if e.last.Before(cutoff) {
						delete(b.paths, pk)
						e.tokens = 0
						e.last = time.Time{}
						entryPool.Put(e)
					}
				}
				if len(b.paths) == 0 && b.last.Before(cutoff) {
					delete(s.ents, k)
					b.tokens = 0
					b.last = time.Time{}
					b.paths = nil
					bucketPool.Put(b)
				}
				continue
			}
			if b.last.Before(cutoff) {
				delete(s.ents, k)
				if b.paths != nil {
					for pk, e := range b.paths {
						delete(b.paths, pk)
						e.tokens = 0
						e.last = time.Time{}
						entryPool.Put(e)
					}
				}
				b.tokens = 0
				b.last = time.Time{}
				b.paths = nil
				bucketPool.Put(b)
			}
		}
		s.mu.Unlock()
	}
}

func (l *Limiter) ActiveBuckets() int {
	if l == nil {
		return 0
	}
	n := 0
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		n += len(s.ents)
		s.mu.Unlock()
	}
	return n
}

func (l *Limiter) Update(requests, burst int, window time.Duration, perPath bool) {
	if l == nil {
		return
	}
	if requests <= 0 {
		return
	}
	if burst <= 0 {
		burst = requests
	}
	if window <= 0 {
		window = time.Minute
	}
	l.requests = requests
	l.burst = burst
	l.window = window
	l.live.Store(&liveCfg{
		rate:    float64(requests) / window.Seconds(),
		burstF:  float64(burst),
		perPath: perPath,
	})
}
