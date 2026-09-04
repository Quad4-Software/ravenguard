// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package protect

import (
	"sync"
	"testing"
	"time"
)

func TestAcquireSweepRace(t *testing.T) {
	g := New(Config{
		Enabled:             true,
		MaxConcurrentGlobal: 10_000,
		MaxConcurrentClient: 100,
	})
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				g.Sweep(time.Millisecond)
			}
		}
	})
	for i := range 16 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := "client-" + string(rune('a'+n%26))
			for range 500 {
				if g.Acquire(key) {
					g.Release(key)
				}
			}
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
	global, _ := g.Concurrency()
	if global != 0 {
		t.Fatalf("global concurrency leak: %d", global)
	}
}

func TestUpdateConfigRace(t *testing.T) {
	g := New(Config{Enabled: true, MaxConcurrentGlobal: 1000, MaxConcurrentClient: 10})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 200 {
			g.UpdateConfig(Config{
				Enabled:             true,
				MaxConcurrentGlobal: 1000,
				MaxConcurrentClient: 10 + i%5,
				BanAfterStrikes:     5,
				BanTTL:              time.Minute,
			})
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			if g.Acquire("k") {
				g.Release("k")
			}
			_ = g.Banned("k")
			g.Strike("k")
		}
	}()
	wg.Wait()
}
