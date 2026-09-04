// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect

import (
	"sync"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/strhash"
)

const behaviorShards = 64

type BehaviorConfig struct {
	Window           time.Duration
	BurstLimit       int
	BurstScore       int
	PathFanout       int
	PathFanoutScore  int
	StrikeLimit      int
	StrikeScore      int
	WriteBurstLimit  int
	WriteBurstScore  int
	WriteRepeatLimit int
	WriteRepeatScore int
}

type BehaviorTracker struct {
	cfg    BehaviorConfig
	shards [behaviorShards]behShard
}

type behShard struct {
	mu   sync.Mutex
	ents map[string]*behEntry
}

type behEntry struct {
	start         time.Time
	reqs          int
	writes        int
	paths         map[string]struct{}
	strikes       int
	lastPath      string
	seqHits       int
	lastWritePath string
	samePathWrite int
}

func NewBehaviorTracker(cfg BehaviorConfig) *BehaviorTracker {
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if cfg.BurstLimit <= 0 {
		cfg.BurstLimit = 60
	}
	if cfg.PathFanout <= 0 {
		cfg.PathFanout = 40
	}
	if cfg.StrikeLimit <= 0 {
		cfg.StrikeLimit = 3
	}
	if cfg.WriteBurstLimit <= 0 {
		cfg.WriteBurstLimit = 20
	}
	if cfg.WriteRepeatLimit <= 0 {
		cfg.WriteRepeatLimit = 8
	}
	t := &BehaviorTracker{cfg: cfg}
	for i := range t.shards {
		t.shards[i].ents = make(map[string]*behEntry)
	}
	return t
}

// Record notes a request for burst, fan-out, and write-spam scoring.
func (t *BehaviorTracker) Record(key, path, method string) {
	if t == nil || key == "" {
		return
	}
	s := &t.shards[strhash.String(key)%behaviorShards]
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e := t.entryLocked(s, key, now)
	e.reqs++
	if e.paths == nil {
		e.paths = make(map[string]struct{})
	}
	if path != "" {
		e.paths[path] = struct{}{}
		if sequentialPath(e.lastPath, path) {
			e.seqHits++
		}
		e.lastPath = path
	}
	if isWriteMethod(method) {
		e.writes++
		// Same-path repeat scoring is limited to spam-prone write segments so
		// general API autosave and cart updates are not challenged early.
		if forumWritePath(path) {
			if path != "" && path == e.lastWritePath {
				e.samePathWrite++
			} else {
				e.lastWritePath = path
				e.samePathWrite = 1
			}
		} else {
			e.lastWritePath = ""
			e.samePathWrite = 0
		}
	}
}

func (t *BehaviorTracker) Strike(key string) {
	if t == nil || key == "" {
		return
	}
	s := &t.shards[strhash.String(key)%behaviorShards]
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e := t.entryLocked(s, key, now)
	e.strikes++
}

func (t *BehaviorTracker) StrikesExceeded(key string) bool {
	if t == nil || key == "" {
		return false
	}
	s := &t.shards[strhash.String(key)%behaviorShards]
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.ents[key]
	if !ok {
		return false
	}
	if now.Sub(e.start) > t.cfg.Window {
		delete(s.ents, key)
		return false
	}
	return e.strikes >= t.cfg.StrikeLimit
}

func (t *BehaviorTracker) Score(key string) Result {
	var res Result
	if t == nil || key == "" {
		return res
	}
	s := &t.shards[strhash.String(key)%behaviorShards]
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.ents[key]
	if !ok {
		return res
	}
	if now.Sub(e.start) > t.cfg.Window {
		delete(s.ents, key)
		return res
	}
	if e.reqs >= t.cfg.BurstLimit && t.cfg.BurstScore > 0 {
		res.Score += t.cfg.BurstScore
		res.Reasons = append(res.Reasons, "behavior_burst")
	}
	if len(e.paths) >= t.cfg.PathFanout && t.cfg.PathFanoutScore > 0 {
		res.Score += t.cfg.PathFanoutScore
		res.Reasons = append(res.Reasons, "behavior_path_fanout")
	}
	if e.seqHits >= 8 && t.cfg.PathFanoutScore > 0 {
		res.Score += t.cfg.PathFanoutScore / 2
		res.Reasons = append(res.Reasons, "behavior_sequential")
	}
	if e.writes >= t.cfg.WriteBurstLimit && t.cfg.WriteBurstScore > 0 {
		res.Score += t.cfg.WriteBurstScore
		res.Reasons = append(res.Reasons, "behavior_write_burst")
	}
	if e.samePathWrite >= t.cfg.WriteRepeatLimit && t.cfg.WriteRepeatScore > 0 {
		res.Score += t.cfg.WriteRepeatScore
		res.Reasons = append(res.Reasons, "behavior_write_repeat")
	}
	if e.strikes > 0 && t.cfg.StrikeScore > 0 {
		res.Score += e.strikes * t.cfg.StrikeScore
		res.Reasons = append(res.Reasons, "behavior_strikes")
	}
	return res
}

func (t *BehaviorTracker) entryLocked(s *behShard, key string, now time.Time) *behEntry {
	e, ok := s.ents[key]
	if !ok || now.Sub(e.start) > t.cfg.Window {
		e = &behEntry{start: now, paths: make(map[string]struct{})}
		s.ents[key] = e
	}
	return e
}

func (t *BehaviorTracker) Sweep(maxAge time.Duration) {
	if t == nil {
		return
	}
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

func sequentialPath(prev, cur string) bool {
	if prev == "" || cur == "" || prev == cur {
		return false
	}
	// Cheap heuristic: trailing numeric segment increments (page/1 -> page/2).
	pi := trailingInt(prev)
	ci := trailingInt(cur)
	if pi < 0 || ci < 0 {
		return false
	}
	return ci == pi+1 && stripTrailingInt(prev) == stripTrailingInt(cur)
}

func trailingInt(s string) int {
	i := len(s) - 1
	if i < 0 || s[i] < '0' || s[i] > '9' {
		return -1
	}
	n := 0
	mult := 1
	for i >= 0 && s[i] >= '0' && s[i] <= '9' {
		n += int(s[i]-'0') * mult
		mult *= 10
		i--
		if n > 1_000_000 {
			return -1
		}
	}
	return n
}

func stripTrailingInt(s string) string {
	i := len(s) - 1
	for i >= 0 && s[i] >= '0' && s[i] <= '9' {
		i--
	}
	if i >= 0 && (s[i] == '/' || s[i] == '-' || s[i] == '_') {
		return s[:i+1]
	}
	return s[:i+1]
}
