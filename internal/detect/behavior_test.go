// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect_test

import (
	"slices"
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

func TestBehaviorWriteRepeatSkipsGeneralAPI(t *testing.T) {
	beh := detect.NewBehaviorTracker(detect.BehaviorConfig{
		Window:           time.Minute,
		BurstLimit:       1000,
		PathFanout:       1000,
		WriteBurstLimit:  100,
		WriteBurstScore:  40,
		WriteRepeatLimit: 3,
		WriteRepeatScore: 45,
	})
	key := "autosave"
	for range 6 {
		beh.Record(key, "/api/v1/documents/save", "POST")
	}
	res := beh.Score(key)
	if containsReason(res.Reasons, "behavior_write_repeat") {
		t.Fatalf("general API autosave must not write-repeat score reasons=%v", res.Reasons)
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

func TestBehaviorForgeBurst(t *testing.T) {
	beh := detect.NewBehaviorTracker(detect.BehaviorConfig{
		Window:          time.Minute,
		BurstLimit:      1000,
		PathFanout:      1000,
		ForgeBurstLimit: 24,
		ForgeBurstScore: 35,
	})
	key := "forge-browser"
	for i := range 23 {
		beh.Record(key, "/o/r/src/branch/main/f"+strconv.Itoa(i), "GET")
	}
	res := beh.Score(key)
	if containsReason(res.Reasons, "behavior_forge_burst") {
		t.Fatalf("23 browse hits must not forge-burst reasons=%v", res.Reasons)
	}
	beh.Record(key, "/o/r/src/branch/main/f23", "GET")
	res = beh.Score(key)
	if !containsReason(res.Reasons, "behavior_forge_burst") {
		t.Fatalf("24 browse hits should forge-burst reasons=%v score=%d", res.Reasons, res.Score)
	}
	if res.Score < 35 {
		t.Fatalf("score=%d", res.Score)
	}
}

func TestBehaviorForgeBurstMixHotBrowse(t *testing.T) {
	beh := detect.NewBehaviorTracker(detect.BehaviorConfig{
		Window:          time.Minute,
		BurstLimit:      1000,
		PathFanout:      1000,
		ForgeBurstLimit: 5,
		ForgeBurstScore: 35,
	})
	key := "mix"
	beh.Record(key, "/o/r/compare/a...b", "GET")
	beh.Record(key, "/o/r/src/branch/main", "GET")
	beh.Record(key, "/o/r/blame/branch/f", "GET")
	beh.Record(key, "/o/r/commits/branch/main", "GET")
	beh.Record(key, "/o/r/archive/main.zip", "GET")
	res := beh.Score(key)
	if !containsReason(res.Reasons, "behavior_forge_burst") {
		t.Fatalf("mixed hot+browse should burst reasons=%v", res.Reasons)
	}
}

func TestBehaviorForgeIgnoresNonForge(t *testing.T) {
	beh := detect.NewBehaviorTracker(detect.BehaviorConfig{
		Window:          time.Minute,
		BurstLimit:      1000,
		PathFanout:      1000,
		ForgeBurstLimit: 3,
		ForgeBurstScore: 35,
	})
	key := "issues"
	for range 10 {
		beh.Record(key, "/o/r/issues", "GET")
	}
	res := beh.Score(key)
	if containsReason(res.Reasons, "behavior_forge_burst") {
		t.Fatalf("issues must not forge-burst reasons=%v", res.Reasons)
	}
}

func containsReason(reasons []string, want string) bool {
	return slices.Contains(reasons, want)
}
