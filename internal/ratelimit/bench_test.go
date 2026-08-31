// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ratelimit_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/ratelimit"
)

func BenchmarkAllow(b *testing.B) {
	l := ratelimit.New(1_000_000, 1_000_000, time.Minute, false)
	b.ReportAllocs()
	for b.Loop() {
		_ = l.Allow("203.0.113.10", "/")
	}
}

func BenchmarkAllowPerPath(b *testing.B) {
	l := ratelimit.New(1_000_000, 1_000_000, time.Minute, true)
	b.ReportAllocs()
	for b.Loop() {
		_ = l.Allow("203.0.113.10", "/api/items")
	}
}

func BenchmarkAllowParallel(b *testing.B) {
	l := ratelimit.New(1_000_000_000, 1_000_000_000, time.Hour, false)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := fmt.Sprintf("203.0.113.%d", i%250)
			_ = l.Allow(ip, "/")
			i++
		}
	})
}

func TestAllowPerPathIndependent(t *testing.T) {
	l := ratelimit.New(10, 1, time.Minute, true)
	if !l.Allow("1.1.1.1", "/a") {
		t.Fatal("a")
	}
	if l.Allow("1.1.1.1", "/a") {
		t.Fatal("a deny")
	}
	if !l.Allow("1.1.1.1", "/b") {
		t.Fatal("b")
	}
}

func TestAllowConcurrent(t *testing.T) {
	l := ratelimit.New(1_000_000, 1_000_000, time.Minute, false)
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := fmt.Sprintf("198.51.100.%d", n)
			for range 1000 {
				if !l.Allow(ip, "/") {
					t.Errorf("deny unexpected")
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
