// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package protect_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/protect"
)

func TestConcurrencyLimit(t *testing.T) {
	g := protect.New(protect.Config{
		Enabled:             true,
		MaxConcurrentGlobal: 2,
		MaxConcurrentClient: 1,
	})
	if !g.Acquire("a") {
		t.Fatal("first")
	}
	if g.Acquire("a") {
		t.Fatal("per-client should fail")
	}
	if !g.Acquire("b") {
		t.Fatal("second global")
	}
	if g.Acquire("c") {
		t.Fatal("global should fail")
	}
	g.Release("a")
	g.Release("b")
	if !g.Acquire("c") {
		t.Fatal("after release")
	}
	g.Release("c")
}

func TestTempBan(t *testing.T) {
	g := protect.New(protect.Config{
		Enabled:         true,
		BanAfterStrikes: 2,
		BanTTL:          time.Minute,
	})
	g.Strike("k")
	if g.Banned("k") {
		t.Fatal("not banned yet")
	}
	g.Strike("k")
	if !g.Banned("k") {
		t.Fatal("expected ban")
	}
}

func TestBanEscalation(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	g := protect.New(protect.Config{
		Enabled:         true,
		BanAfterStrikes: 2,
		BanTTL:          200 * time.Millisecond,
		BanEscalation:   3,
	})
	g.Strike("k")
	g.Strike("k")
	if !g.Banned("k") {
		t.Fatal("first ban")
	}

	// Wait for the first ban to expire, simulating a yo-yo backoff.
	time.Sleep(300 * time.Millisecond)
	if g.Banned("k") {
		t.Fatal("ban should have expired")
	}

	// Re-offend. The second ban should be longer (2x) because bans memory persists.
	g.Strike("k")
	g.Strike("k")
	if !g.Banned("k") {
		t.Fatal("second ban")
	}
	info := g.ListBans()
	if len(info) != 1 || info[0].Bans != 2 {
		t.Fatalf("expected bans=2, got %v", info)
	}
	if time.Until(info[0].BannedUntil) < 250*time.Millisecond {
		t.Fatalf("second ban TTL not escalated: until=%v", info[0].BannedUntil)
	}
}

func TestRequestSize(t *testing.T) {
	g := protect.New(protect.Config{
		Enabled:      true,
		MaxURLBytes:  20,
		MaxBodyBytes: 10,
	})
	r := httptest.NewRequest(http.MethodGet, "/this/path/is/way/too/long/for/limit", nil)
	if g.CheckRequestSize(r) == "" {
		t.Fatal("expected url too large")
	}
	r2 := httptest.NewRequest(http.MethodPost, "/", nil)
	r2.ContentLength = 100
	if g.CheckRequestSize(r2) == "" {
		t.Fatal("expected body too large")
	}
}

func TestMethodCost(t *testing.T) {
	if protect.MethodCost(http.MethodGet, 3) != 1 {
		t.Fatal("get")
	}
	if protect.MethodCost(http.MethodPost, 3) != 3 {
		t.Fatal("post")
	}
}
