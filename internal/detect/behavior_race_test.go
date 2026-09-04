// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect

import (
	"sync"
	"testing"
	"time"
)

func TestBehaviorForgeBurstRace(t *testing.T) {
	beh := NewBehaviorTracker(BehaviorConfig{
		Window:          time.Minute,
		BurstLimit:      1_000_000,
		PathFanout:      1_000_000,
		ForgeBurstLimit: 10,
		ForgeBurstScore: 35,
	})
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := "race-key"
			if id%2 == 0 {
				key = "other-key"
			}
			for i := range 200 {
				if i%2 == 0 {
					beh.Record(key, "/o/r/compare/a...b", "GET")
				} else {
					beh.Record(key, "/o/r/src/branch/main", "GET")
				}
				_ = beh.Score(key)
			}
		}(g)
	}
	wg.Wait()
	res := beh.Score("race-key")
	if res.Score < 0 {
		t.Fatalf("negative score %d", res.Score)
	}
}
