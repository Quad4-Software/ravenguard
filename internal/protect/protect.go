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
	cfg     atomic.Pointer[Config]
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
	g := &Guard{}
	cp := cfg
	g.cfg.Store(&cp)
	for i := range g.bans {
		g.bans[i].ents = make(map[string]*banEntry)
	}
	return g
}

func (g *Guard) live() Config {
	if g == nil {
		return Config{}
	}
	if p := g.cfg.Load(); p != nil {
		return *p
	}
	return Config{}
}

func (g *Guard) Enabled() bool {
	return g != nil && g.live().Enabled
}

func (g *Guard) MaxBodyBytes() int64 {
	if g == nil {
		return 1 << 20
	}
	return g.live().MaxBodyBytes
}

func (g *Guard) MaxHeaderBytes() int {
	if g == nil {
		return 1 << 14
	}
	return g.live().MaxHeaderBytes
}

func (g *Guard) WriteCost() int {
	if g == nil {
		return 3
	}
	c := g.live().WriteMethodCost
	if c <= 0 {
		return 3
	}
	return c
}

func (g *Guard) AttackBlock() bool {
	return g != nil && g.live().AttackBlock
}

func (g *Guard) AttackScore() int {
	if g == nil {
		return 90
	}
	return g.live().AttackScore
}

func (g *Guard) CheckRequestSize(r *http.Request) string {
	cfg := g.live()
	if g == nil || !cfg.Enabled || r == nil || r.URL == nil {
		return ""
	}
	n := len(r.URL.Path)
	if q := r.URL.RawQuery; q != "" {
		n += 1 + len(q)
	}
	if n > cfg.MaxURLBytes {
		return "url too large"
	}
	if r.ContentLength > cfg.MaxBodyBytes {
		return "body too large"
	}
	return ""
}

func (g *Guard) LimitBody(w http.ResponseWriter, r *http.Request) {
	cfg := g.live()
	if g == nil || !cfg.Enabled || r == nil || r.Body == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)
}

func (g *Guard) Acquire(key string) bool {
	cfg := g.live()
	if g == nil || !cfg.Enabled {
		return true
	}
	for {
		cur := g.global.Load()
		if cur >= cfg.MaxConcurrentGlobal {
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
	if int(n) > cfg.MaxConcurrentClient {
		c.n.Add(-1)
		g.global.Add(-1)
		return false
	}
	// Sweep may delete idle entries. If our slot vanished after Add,
	// re-publish the same counter so Release and later Acquires stay consistent.
	if cur, ok := g.clients.Load(key); !ok || cur != c {
		g.clients.Store(key, c)
	}
	return true
}

func (g *Guard) Release(key string) {
	if g == nil || !g.live().Enabled {
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
	if g == nil || !g.live().Enabled || key == "" {
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
	cfg := g.live()
	if g == nil || !cfg.Enabled || key == "" {
		return
	}
	s := &g.bans[strhash.String(key)%banShards]
	now := time.Now()
	s.mu.Lock()
	e, ok := s.ents[key]
	if !ok || now.Sub(e.windowStart) > cfg.BanTTL {
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
	if e.strikes >= cfg.BanAfterStrikes {
		e.bannedUntil = now.Add(cfg.BanTTL)
	}
	s.mu.Unlock()
}

func (g *Guard) BanNow(key string) {
	cfg := g.live()
	if g == nil || !cfg.Enabled || key == "" {
		return
	}
	g.BanUntil(key, time.Now().Add(cfg.BanTTL))
}

// BanUntil sets an absolute ban expiry for key.
func (g *Guard) BanUntil(key string, until time.Time) {
	cfg := g.live()
	if g == nil || !cfg.Enabled || key == "" || until.IsZero() {
		return
	}
	s := &g.bans[strhash.String(key)%banShards]
	now := time.Now()
	if until.Before(now) {
		return
	}
	s.mu.Lock()
	if old, ok := s.ents[key]; ok {
		old.bannedUntil = time.Time{}
		old.strikes = 0
		old.windowStart = time.Time{}
		banEntryPool.Put(old)
	}
	e := banEntryPool.Get().(*banEntry)
	e.strikes = cfg.BanAfterStrikes
	e.windowStart = now
	e.bannedUntil = until
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
		c := value.(*clientConc)
		if c.n.Load() != 0 {
			return true
		}
		// CompareAndDelete avoids removing a slot another goroutine just reused
		// with a different *clientConc. Acquire re-Stores if a race still lands.
		g.clients.CompareAndDelete(key, value)
		return true
	})
}

// BanInfo is a snapshot of a ban or strike entry.
type BanInfo struct {
	Key         string    `json:"key"`
	Strikes     int       `json:"strikes"`
	BannedUntil time.Time `json:"banned_until"`
	WindowStart time.Time `json:"window_start"`
	Active      bool      `json:"active"`
}

func (g *Guard) ListBans() []BanInfo {
	if g == nil {
		return nil
	}
	now := time.Now()
	var out []BanInfo
	for i := range g.bans {
		s := &g.bans[i]
		s.mu.Lock()
		for k, e := range s.ents {
			active := !e.bannedUntil.IsZero() && now.Before(e.bannedUntil)
			if !active && e.strikes == 0 {
				continue
			}
			out = append(out, BanInfo{
				Key:         k,
				Strikes:     e.strikes,
				BannedUntil: e.bannedUntil,
				WindowStart: e.windowStart,
				Active:      active,
			})
		}
		s.mu.Unlock()
	}
	return out
}

func (g *Guard) Unban(key string) bool {
	if g == nil || key == "" {
		return false
	}
	s := &g.bans[strhash.String(key)%banShards]
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.ents[key]
	if !ok {
		return false
	}
	delete(s.ents, key)
	e.bannedUntil = time.Time{}
	e.strikes = 0
	e.windowStart = time.Time{}
	banEntryPool.Put(e)
	return true
}

func (g *Guard) ClearStrikes(key string) bool {
	return g.Unban(key)
}

func (g *Guard) BanCount() int {
	if g == nil {
		return 0
	}
	now := time.Now()
	n := 0
	for i := range g.bans {
		s := &g.bans[i]
		s.mu.Lock()
		for _, e := range s.ents {
			if !e.bannedUntil.IsZero() && now.Before(e.bannedUntil) {
				n++
			}
		}
		s.mu.Unlock()
	}
	return n
}

func (g *Guard) Concurrency() (global int64, clients int) {
	if g == nil {
		return 0, 0
	}
	g.clients.Range(func(_, _ any) bool {
		clients++
		return true
	})
	return g.global.Load(), clients
}

func (g *Guard) UpdateConfig(cfg Config) {
	if g == nil {
		return
	}
	cur := g.live()
	if cfg.BanAfterStrikes > 0 {
		cur.BanAfterStrikes = cfg.BanAfterStrikes
	}
	if cfg.BanTTL > 0 {
		cur.BanTTL = cfg.BanTTL
	}
	if cfg.MaxBodyBytes > 0 {
		cur.MaxBodyBytes = cfg.MaxBodyBytes
	}
	if cfg.MaxHeaderBytes > 0 {
		cur.MaxHeaderBytes = cfg.MaxHeaderBytes
	}
	if cfg.MaxURLBytes > 0 {
		cur.MaxURLBytes = cfg.MaxURLBytes
	}
	if cfg.MaxConcurrentGlobal > 0 {
		cur.MaxConcurrentGlobal = cfg.MaxConcurrentGlobal
	}
	if cfg.MaxConcurrentClient > 0 {
		cur.MaxConcurrentClient = cfg.MaxConcurrentClient
	}
	cur.AttackBlock = cfg.AttackBlock
	if cfg.AttackScore > 0 {
		cur.AttackScore = cfg.AttackScore
	}
	if cfg.WriteMethodCost > 0 {
		cur.WriteMethodCost = cfg.WriteMethodCost
	}
	cur.Enabled = cfg.Enabled
	g.cfg.Store(&cur)
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
