// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package protect

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/strhash"
)

const banShards = 64

type Config struct {
	Enabled             bool
	MaxBodyBytes        int64
	MaxHeaderBytes      int
	MaxURLBytes         int
	MaxConcurrentGlobal int64
	MaxConcurrentClient int
	BanAfterStrikes     int
	BanTTL              time.Duration
	AttackBlock         bool
	AttackScore         int
	WriteMethodCost     int
}

type Guard struct {
	cfg     Config
	global  atomic.Int64
	clients sync.Map
	bans    [banShards]banShard
}

type clientConc struct {
	n atomic.Int64
}

type banShard struct {
	mu   sync.Mutex
	ents map[string]*banEntry
}

type banEntry struct {
	bannedUntil time.Time
	strikes     int
	windowStart time.Time
}

var banEntryPool = sync.Pool{
	New: func() any {
		return &banEntry{}
	},
}

func New(cfg Config) *Guard {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.MaxHeaderBytes <= 0 {
		cfg.MaxHeaderBytes = 1 << 14
	}
	if cfg.MaxURLBytes <= 0 {
		cfg.MaxURLBytes = 8192
	}
	if cfg.MaxConcurrentGlobal <= 0 {
		cfg.MaxConcurrentGlobal = 2048
	}
	if cfg.MaxConcurrentClient <= 0 {
		cfg.MaxConcurrentClient = 16
	}
	if cfg.BanAfterStrikes <= 0 {
		cfg.BanAfterStrikes = 5
	}
	if cfg.BanTTL <= 0 {
		cfg.BanTTL = 10 * time.Minute
	}
	if cfg.WriteMethodCost <= 0 {
		cfg.WriteMethodCost = 3
	}
	if cfg.AttackScore <= 0 {
		cfg.AttackScore = 90
	}
	g := &Guard{cfg: cfg}
	for i := range g.bans {
		g.bans[i].ents = make(map[string]*banEntry)
	}
	return g
}

func (g *Guard) Enabled() bool {
	return g != nil && g.cfg.Enabled
}

func (g *Guard) MaxBodyBytes() int64 {
	if g == nil {
		return 1 << 20
	}
	return g.cfg.MaxBodyBytes
}

func (g *Guard) MaxHeaderBytes() int {
	if g == nil {
		return 1 << 14
	}
	return g.cfg.MaxHeaderBytes
}

func (g *Guard) WriteCost() int {
	if g == nil || g.cfg.WriteMethodCost <= 0 {
		return 3
	}
	return g.cfg.WriteMethodCost
}

func (g *Guard) AttackBlock() bool {
	return g != nil && g.cfg.AttackBlock
}

func (g *Guard) AttackScore() int {
	if g == nil {
		return 90
	}
	return g.cfg.AttackScore
}

func (g *Guard) CheckRequestSize(r *http.Request) string {
	if g == nil || !g.cfg.Enabled || r == nil || r.URL == nil {
		return ""
	}
	n := len(r.URL.Path)
	if q := r.URL.RawQuery; q != "" {
		n += 1 + len(q)
	}
	if n > g.cfg.MaxURLBytes {
		return "url too large"
	}
	if r.ContentLength > g.cfg.MaxBodyBytes {
		return "body too large"
	}
	return ""
}

func (g *Guard) LimitBody(w http.ResponseWriter, r *http.Request) {
	if g == nil || !g.cfg.Enabled || r == nil || r.Body == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, g.cfg.MaxBodyBytes)
}

func (g *Guard) Acquire(key string) bool {
	if g == nil || !g.cfg.Enabled {
		return true
	}
	for {
		cur := g.global.Load()
		if cur >= g.cfg.MaxConcurrentGlobal {
			return false
		}
		if g.global.CompareAndSwap(cur, cur+1) {
			break
		}
	}
	if key == "" {
		return true
	}
	v, _ := g.clients.LoadOrStore(key, &clientConc{})
	c := v.(*clientConc)
	n := c.n.Add(1)
	if int(n) > g.cfg.MaxConcurrentClient {
		c.n.Add(-1)
		g.global.Add(-1)
		return false
	}
	return true
}

func (g *Guard) Release(key string) {
	if g == nil || !g.cfg.Enabled {
		return
	}
	g.global.Add(-1)
	if key == "" {
		return
	}
	if v, ok := g.clients.Load(key); ok {
		v.(*clientConc).n.Add(-1)
	}
}

func (g *Guard) Banned(key string) bool {
	if g == nil || !g.cfg.Enabled || key == "" {
		return false
	}
	s := &g.bans[strhash.String(key)%banShards]
	now := time.Now()
	s.mu.Lock()
	e, ok := s.ents[key]
	if !ok {
		s.mu.Unlock()
		return false
	}
	if e.bannedUntil.IsZero() || now.After(e.bannedUntil) {
		if !e.bannedUntil.IsZero() && now.After(e.bannedUntil) {
			delete(s.ents, key)
			e.bannedUntil = time.Time{}
			e.strikes = 0
			e.windowStart = time.Time{}
			banEntryPool.Put(e)
		}
		s.mu.Unlock()
		return false
	}
	s.mu.Unlock()
	return true
}

func (g *Guard) Strike(key string) {
	if g == nil || !g.cfg.Enabled || key == "" {
		return
	}
	s := &g.bans[strhash.String(key)%banShards]
	now := time.Now()
	s.mu.Lock()
	e, ok := s.ents[key]
	if !ok || now.Sub(e.windowStart) > g.cfg.BanTTL {
		if ok {
			e.bannedUntil = time.Time{}
			e.strikes = 0
			e.windowStart = time.Time{}
			banEntryPool.Put(e)
		}
		e = banEntryPool.Get().(*banEntry)
		e.strikes = 1
		e.windowStart = now
		e.bannedUntil = time.Time{}
		s.ents[key] = e
		s.mu.Unlock()
		return
	}
	e.strikes++
	if e.strikes >= g.cfg.BanAfterStrikes {
		e.bannedUntil = now.Add(g.cfg.BanTTL)
	}
	s.mu.Unlock()
}

func (g *Guard) BanNow(key string) {
	if g == nil || !g.cfg.Enabled || key == "" {
		return
	}
	s := &g.bans[strhash.String(key)%banShards]
	now := time.Now()
	s.mu.Lock()
	if old, ok := s.ents[key]; ok {
		old.bannedUntil = time.Time{}
		old.strikes = 0
		old.windowStart = time.Time{}
		banEntryPool.Put(old)
	}
	e := banEntryPool.Get().(*banEntry)
	e.strikes = g.cfg.BanAfterStrikes
	e.windowStart = now
	e.bannedUntil = now.Add(g.cfg.BanTTL)
	s.ents[key] = e
	s.mu.Unlock()
}

func (g *Guard) Sweep(maxAge time.Duration) {
	if g == nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for i := range g.bans {
		s := &g.bans[i]
		s.mu.Lock()
		for k, e := range s.ents {
			if (!e.bannedUntil.IsZero() && e.bannedUntil.Before(cutoff)) ||
				(e.bannedUntil.IsZero() && e.windowStart.Before(cutoff)) {
				delete(s.ents, k)
				e.bannedUntil = time.Time{}
				e.strikes = 0
				e.windowStart = time.Time{}
				banEntryPool.Put(e)
			}
		}
		s.mu.Unlock()
	}
	g.clients.Range(func(key, value any) bool {
		if value.(*clientConc).n.Load() == 0 {
			g.clients.Delete(key)
		}
		return true
	})
}

func MethodCost(method string, writeCost int) int {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		if writeCost <= 0 {
			return 3
		}
		return writeCost
	default:
		return 1
	}
}
