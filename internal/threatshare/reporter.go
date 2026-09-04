// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package threatshare

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

// Reporter sends threat entries to the hub asynchronously.
type Reporter struct {
	Send       func(ctx context.Context, entries []agentprotocol.ThreatEntry) error
	DefaultTTL time.Duration

	mu     sync.Mutex
	queue  []agentprotocol.ThreatEntry
	closed chan struct{}
	once   sync.Once
}

func NewReporter(send func(ctx context.Context, entries []agentprotocol.ThreatEntry) error, ttl time.Duration) *Reporter {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	r := &Reporter{
		Send:       send,
		DefaultTTL: ttl,
		closed:     make(chan struct{}),
	}
	go r.loop()
	return r
}

func (r *Reporter) Close() {
	if r == nil {
		return
	}
	r.once.Do(func() { close(r.closed) })
}

// ReportBind enqueues a privacy bind-key ban for fleet share.
func (r *Reporter) ReportBind(key, reason string) {
	r.enqueue(agentprotocol.ThreatKeyBind, key, reason)
}

// ReportUA enqueues a UA substring block.
func (r *Reporter) ReportUA(ua, reason string) {
	ua = strings.TrimSpace(ua)
	if len(ua) > 120 {
		ua = ua[:120]
	}
	r.enqueue(agentprotocol.ThreatKeyUA, strings.ToLower(ua), reason)
}

func (r *Reporter) enqueue(keyType, key, reason string) {
	if r == nil || r.Send == nil || key == "" {
		return
	}
	reason = strings.TrimSpace(reason)
	if len(reason) > maxReasonLen {
		reason = reason[:maxReasonLen]
	}
	now := time.Now()
	e := agentprotocol.ThreatEntry{
		KeyType:       keyType,
		Key:           key,
		TTLSeconds:    int64(r.DefaultTTL / time.Second),
		Reason:        reason,
		CreatedAtUnix: now.Unix(),
		ExpiresAtUnix: now.Add(r.DefaultTTL).Unix(),
	}
	r.mu.Lock()
	if len(r.queue) >= 1024 {
		r.mu.Unlock()
		return
	}
	r.queue = append(r.queue, e)
	r.mu.Unlock()
}

func (r *Reporter) loop() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.closed:
			r.flush()
			return
		case <-ticker.C:
			r.flush()
		}
	}
}

func (r *Reporter) flush() {
	r.mu.Lock()
	batch := r.queue
	r.queue = nil
	r.mu.Unlock()
	if len(batch) == 0 || r.Send == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := r.Send(ctx, batch); err != nil {
		slog.Debug("threat report", "err", err, "n", len(batch))
	}
}
