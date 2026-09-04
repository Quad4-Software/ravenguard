// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ml

import (
	"encoding/json"
	"math/rand"
	"sync"
	"time"
)

// Sample is one shadow observation for labeling / adapt.
type Sample struct {
	Ray        string              `json:"ray"`
	CreatedAt  time.Time           `json:"created_at"`
	Prob       float64             `json:"prob"`
	Points     int                 `json:"points"`
	WouldBlock bool                `json:"would_block"`
	WouldChal  bool                `json:"would_challenge"`
	Features   [FeatureDim]float32 `json:"features"`
	Label      string              `json:"label,omitempty"`
	Method     string              `json:"method"`
	Path       string              `json:"path"`
	Host       string              `json:"host"`
}

// SampleSink persists samples asynchronously.
type SampleSink interface {
	InsertMLSample(s Sample) error
}

// ShadowLog is a non-blocking ring + optional async sink.
type ShadowLog struct {
	ch     chan Sample
	sink   SampleSink
	mu     sync.Mutex
	closed bool
}

// NewShadowLog creates a bounded queue.
func NewShadowLog(buf int) *ShadowLog {
	if buf < 64 {
		buf = 64
	}
	s := &ShadowLog{ch: make(chan Sample, buf)}
	go s.loop()
	return s
}

// SetSink attaches durable storage.
func (s *ShadowLog) SetSink(sink SampleSink) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.sink = sink
	s.mu.Unlock()
}

// Offer enqueues or drops. never blocks.
func (s *ShadowLog) Offer(sample Sample) {
	if s == nil {
		return
	}
	select {
	case s.ch <- sample:
	default:
	}
}

// MaybeSampleAllow samples allow-path traffic at rate in [0,1].
func (s *ShadowLog) MaybeSampleAllow(rate float64, sample Sample) {
	if s == nil || rate <= 0 {
		return
	}
	if rate >= 1 || rand.Float64() < rate {
		s.Offer(sample)
	}
}

func (s *ShadowLog) loop() {
	for sample := range s.ch {
		s.mu.Lock()
		sink := s.sink
		s.mu.Unlock()
		if sink != nil {
			_ = sink.InsertMLSample(sample)
		}
	}
}

// Close stops the worker.
func (s *ShadowLog) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.ch)
	s.mu.Unlock()
}

// SampleJSON marshals features for SQL.
func SampleJSON(feats [FeatureDim]float32) string {
	b, err := json.Marshal(feats)
	if err != nil {
		return "[]"
	}
	return string(b)
}
