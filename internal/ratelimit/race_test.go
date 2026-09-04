// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestUpdateAllowRace(t *testing.T) {
	l := New(100, 100, time.Second, false)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			l.Update(100+i%10, 200, time.Second, i%2 == 0)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			_ = l.AllowN("1.2.3.4", "/x", 1)
		}
	}()
	wg.Wait()
}
