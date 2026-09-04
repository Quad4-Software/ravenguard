// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package threatshare

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
	"github.com/Quad4-Software/ravenguard/internal/protect"
	"github.com/Quad4-Software/ravenguard/internal/strhash"
)

const (
	defaultMaxEntries = 50000
	maxReasonLen      = 128
	maxKeyLen         = 256
)

// Overlay holds shared UA/IP/JA4 blocks applied from the fleet ledger.
type Overlay struct {
	mu      sync.RWMutex
	ua      map[string]time.Time
	ip      map[string]time.Time
	ja4     map[string]time.Time
	seen    map[string]struct{}
	maxEnts int
}

func NewOverlay(maxEntries int) *Overlay {
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	return &Overlay{
		ua:      make(map[string]time.Time),
		ip:      make(map[string]time.Time),
		ja4:     make(map[string]time.Time),
		seen:    make(map[string]struct{}),
		maxEnts: maxEntries,
	}
}

// Applier applies threat entries onto protect bans and the overlay.
type Applier struct {
	Protect *protect.Guard
	Overlay *Overlay
}

func (a *Applier) Apply(entries []agentprotocol.ThreatEntry) int {
	if a == nil || len(entries) == 0 {
		return 0
	}
	now := time.Now()
	n := 0
	for _, e := range entries {
		if !ApplyOne(a.Protect, a.Overlay, e, now) {
			continue
		}
		n++
	}
	return n
}

// ApplyOne validates and applies a single entry. Returns false if ignored.
func ApplyOne(prot *protect.Guard, ov *Overlay, e agentprotocol.ThreatEntry, now time.Time) bool {
	e.KeyType = strings.ToLower(strings.TrimSpace(e.KeyType))
	e.Key = strings.TrimSpace(e.Key)
	e.Reason = strings.TrimSpace(e.Reason)
	if e.Key == "" || e.KeyType == "" {
		return false
	}
	if len(e.Key) > maxKeyLen || len(e.Reason) > maxReasonLen {
		return false
	}
	exp := expiry(e, now)
	if !exp.After(now) {
		return false
	}
	if ov != nil && e.ID != "" {
		ov.mu.Lock()
		if _, ok := ov.seen[e.ID]; ok {
			ov.mu.Unlock()
			return false
		}
		if len(ov.seen) >= ov.maxEnts {
			ov.mu.Unlock()
			return false
		}
		ov.seen[e.ID] = struct{}{}
		ov.mu.Unlock()
	}
	switch e.KeyType {
	case agentprotocol.ThreatKeyBind, agentprotocol.ThreatKeyIPHash:
		if prot == nil {
			return false
		}
		prot.BanUntil(e.Key, exp)
		return true
	case agentprotocol.ThreatKeyUA:
		if ov == nil {
			return false
		}
		ov.putUA(e.Key, exp)
		return true
	case agentprotocol.ThreatKeyIP:
		if ov == nil {
			return false
		}
		if net.ParseIP(e.Key) == nil {
			return false
		}
		ov.putIP(e.Key, exp)
		return true
	case agentprotocol.ThreatKeyJA4:
		if ov == nil {
			return false
		}
		ov.putJA4(e.Key, exp)
		return true
	default:
		return false
	}
}

func expiry(e agentprotocol.ThreatEntry, now time.Time) time.Time {
	if e.ExpiresAtUnix > 0 {
		return time.Unix(e.ExpiresAtUnix, 0)
	}
	ttl := e.TTLSeconds
	if ttl <= 0 {
		ttl = 600
	}
	return now.Add(time.Duration(ttl) * time.Second)
}

func (o *Overlay) putUA(key string, exp time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.ua[strings.ToLower(key)] = exp
}

func (o *Overlay) putIP(key string, exp time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.ip[key] = exp
}

func (o *Overlay) putJA4(key string, exp time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.ja4[strings.ToLower(key)] = exp
}

func (o *Overlay) UABlocked(ua string) bool {
	if o == nil || ua == "" {
		return false
	}
	low := strings.ToLower(ua)
	now := time.Now()
	o.mu.RLock()
	defer o.mu.RUnlock()
	for needle, exp := range o.ua {
		if now.After(exp) {
			continue
		}
		if strings.Contains(low, needle) {
			return true
		}
	}
	return false
}

func (o *Overlay) IPBlocked(ip net.IP) bool {
	if o == nil || ip == nil {
		return false
	}
	key := ip.String()
	now := time.Now()
	o.mu.RLock()
	exp, ok := o.ip[key]
	o.mu.RUnlock()
	return ok && now.Before(exp)
}

func (o *Overlay) JA4Blocked(ja4 string) bool {
	if o == nil || ja4 == "" {
		return false
	}
	now := time.Now()
	o.mu.RLock()
	exp, ok := o.ja4[strings.ToLower(ja4)]
	o.mu.RUnlock()
	return ok && now.Before(exp)
}

// Sweep removes expired overlay entries.
func (o *Overlay) Sweep() {
	if o == nil {
		return
	}
	now := time.Now()
	o.mu.Lock()
	defer o.mu.Unlock()
	for k, exp := range o.ua {
		if now.After(exp) {
			delete(o.ua, k)
		}
	}
	for k, exp := range o.ip {
		if now.After(exp) {
			delete(o.ip, k)
		}
	}
	for k, exp := range o.ja4 {
		if now.After(exp) {
			delete(o.ja4, k)
		}
	}
	if len(o.seen) > o.maxEnts/2 {
		o.seen = make(map[string]struct{}, len(o.seen)/2)
	}
}

func (o *Overlay) Stats() map[string]int {
	if o == nil {
		return map[string]int{}
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return map[string]int{
		"ua":   len(o.ua),
		"ip":   len(o.ip),
		"ja4":  len(o.ja4),
		"seen": len(o.seen),
	}
}

// ShardKey is a stable hash for tests and sharding helpers.
func ShardKey(key string) uint32 {
	return strhash.String(key)
}
