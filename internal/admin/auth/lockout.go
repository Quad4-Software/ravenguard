// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package auth

import (
	"sync"
	"time"
)

const (
	maxFailures = 8
	lockTTL     = 15 * time.Minute
)

type lockEntry struct {
	failures int
	until    time.Time
}

// Lockout tracks failed logins per key (username or IP).
type Lockout struct {
	mu   sync.Mutex
	ents map[string]*lockEntry
}

func NewLockout() *Lockout {
	return &Lockout{ents: make(map[string]*lockEntry)}
}

func (l *Lockout) Locked(key string) bool {
	if key == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.ents[key]
	if !ok {
		return false
	}
	if time.Now().After(e.until) {
		delete(l.ents, key)
		return false
	}
	return e.failures >= maxFailures
}

func (l *Lockout) Fail(key string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.ents[key]
	now := time.Now()
	if !ok || now.After(e.until) {
		e = &lockEntry{failures: 1, until: now.Add(lockTTL)}
		l.ents[key] = e
		return
	}
	e.failures++
	e.until = now.Add(lockTTL)
}

func (l *Lockout) Clear(key string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	delete(l.ents, key)
	l.mu.Unlock()
}
