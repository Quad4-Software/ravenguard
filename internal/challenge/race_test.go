// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge

import (
	"sync"
	"testing"
	"time"
)

func TestApplyLiveRace(t *testing.T) {
	m := &Manager{
		Secret:     []byte("test-secret-32-bytes-padding!!"),
		Difficulty: 8,
		Algorithm:  "sha256",
		CookieName: "rg_clear",
		CookieTTL:  time.Hour,
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			m.ApplyLive("rg_clear", 8+i%4, time.Hour, "sha256")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _, _ = m.Issue("bind")
			_ = m.settings()
		}
	}()
	wg.Wait()
}
