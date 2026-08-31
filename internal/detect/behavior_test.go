// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/detect"
)

func TestBehaviorBurstAndFanout(t *testing.T) {
	beh := detect.NewBehaviorTracker(detect.BehaviorConfig{
		Window:          time.Minute,
		BurstLimit:      5,
		BurstScore:      35,
		PathFanout:      4,
		PathFanoutScore: 30,
		StrikeLimit:     3,
		StrikeScore:     25,
	})
	key := "client-a"
	for i := range 5 {
		beh.Record(key, "/p/"+strconv.Itoa(i))
	}
	res := beh.Score(key)
	if res.Score < 35 {
		t.Fatalf("score=%d", res.Score)
	}
}

func TestBehaviorStrikes(t *testing.T) {
	beh := detect.NewBehaviorTracker(detect.BehaviorConfig{
		Window:      time.Minute,
		StrikeLimit: 2,
		StrikeScore: 25,
		BurstLimit:  1000,
		PathFanout:  1000,
	})
	key := "client-b"
	beh.Strike(key)
	if beh.StrikesExceeded(key) {
		t.Fatal("should not exceed yet")
	}
	beh.Strike(key)
	if !beh.StrikesExceeded(key) {
		t.Fatal("expected strike limit")
	}
	res := beh.Score(key)
	if res.Score < 50 {
		t.Fatalf("score=%d", res.Score)
	}
}
