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
		beh.Record(key, "/p/"+strconv.Itoa(i), "GET")
	}
	res := beh.Score(key)
	if res.Score < 35 {
		t.Fatalf("score=%d", res.Score)
	}
}

func TestBehaviorWriteBurstAndRepeat(t *testing.T) {
	beh := detect.NewBehaviorTracker(detect.BehaviorConfig{
		Window:           time.Minute,
		BurstLimit:       1000,
		PathFanout:       1000,
		WriteBurstLimit:  4,
		WriteBurstScore:  40,
		WriteRepeatLimit: 3,
		WriteRepeatScore: 45,
	})
	key := "spammer"
	for range 4 {
		beh.Record(key, "/comment", "POST")
	}
	res := beh.Score(key)
	if res.Score < 40 {
		t.Fatalf("write burst score=%d reasons=%v", res.Score, res.Reasons)
	}
	if !containsReason(res.Reasons, "behavior_write_burst") {
		t.Fatalf("missing write burst reasons=%v", res.Reasons)
	}
	if !containsReason(res.Reasons, "behavior_write_repeat") {
		t.Fatalf("missing write repeat reasons=%v", res.Reasons)
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

func containsReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}
