// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package threatshare_test

import (
	"bytes"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
	"github.com/Quad4-Software/ravenguard/internal/protect"
	"github.com/Quad4-Software/ravenguard/internal/threatshare"
)

func TestApplyBindAndUA(t *testing.T) {
	prot := protect.New(protect.Config{
		Enabled: true, BanAfterStrikes: 1, BanTTL: time.Minute,
	})
	ov := threatshare.NewOverlay(100)
	ap := &threatshare.Applier{Protect: prot, Overlay: ov}
	now := time.Now()
	n := ap.Apply([]agentprotocol.ThreatEntry{
		{ID: "1", KeyType: agentprotocol.ThreatKeyBind, Key: "bind-abc", ExpiresAtUnix: now.Add(time.Minute).Unix()},
		{ID: "2", KeyType: agentprotocol.ThreatKeyUA, Key: "badbot", ExpiresAtUnix: now.Add(time.Minute).Unix()},
		{ID: "1", KeyType: agentprotocol.ThreatKeyBind, Key: "bind-abc", ExpiresAtUnix: now.Add(time.Minute).Unix()},
	})
	if n != 2 {
		t.Fatalf("applied %d want 2", n)
	}
	if !prot.Banned("bind-abc") {
		t.Fatal("expected ban")
	}
	if !ov.UABlocked("Mozilla BadBot/1.0") {
		t.Fatal("expected ua block")
	}
}

func TestApplyRejectsExpiredAndBadIP(t *testing.T) {
	ov := threatshare.NewOverlay(10)
	now := time.Now()
	if threatshare.ApplyOne(nil, ov, agentprotocol.ThreatEntry{
		ID: "x", KeyType: agentprotocol.ThreatKeyIP, Key: "not-an-ip", ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}, now) {
		t.Fatal("bad ip should fail")
	}
	if threatshare.ApplyOne(nil, ov, agentprotocol.ThreatEntry{
		ID: "y", KeyType: agentprotocol.ThreatKeyUA, Key: "x", ExpiresAtUnix: now.Add(-time.Minute).Unix(),
	}, now) {
		t.Fatal("expired should fail")
	}
}

func TestOverlayIPJA4(t *testing.T) {
	ov := threatshare.NewOverlay(10)
	now := time.Now()
	threatshare.ApplyOne(nil, ov, agentprotocol.ThreatEntry{
		ID: "ip", KeyType: agentprotocol.ThreatKeyIP, Key: "203.0.113.9", ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}, now)
	threatshare.ApplyOne(nil, ov, agentprotocol.ThreatEntry{
		ID: "j", KeyType: agentprotocol.ThreatKeyJA4, Key: "t13d", ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}, now)
	if !ov.IPBlocked(net.ParseIP("203.0.113.9")) {
		t.Fatal("ip")
	}
	if !ov.JA4Blocked("T13D") {
		t.Fatal("ja4")
	}
}

func TestApplyRace(t *testing.T) {
	prot := protect.New(protect.Config{
		Enabled: true, BanAfterStrikes: 1, BanTTL: time.Minute,
	})
	ov := threatshare.NewOverlay(10000)
	ap := &threatshare.Applier{Protect: prot, Overlay: ov}
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := range 100 {
				id := time.Now().Format("15:04:05.000000000") + string(rune('a'+n)) + string(rune('0'+j%10))
				ap.Apply([]agentprotocol.ThreatEntry{{
					ID: id, KeyType: agentprotocol.ThreatKeyBind,
					Key: "k", ExpiresAtUnix: time.Now().Add(time.Minute).Unix(),
				}})
				_ = ov.UABlocked("x")
				ov.Sweep()
			}
		}(i)
	}
	wg.Wait()
}

func TestLeakageNoRawInLogs(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	_ = log
	ov := threatshare.NewOverlay(10)
	now := time.Now()
	threatshare.ApplyOne(nil, ov, agentprotocol.ThreatEntry{
		ID: "1", KeyType: agentprotocol.ThreatKeyIP, Key: "198.51.100.7",
		ExpiresAtUnix: now.Add(time.Minute).Unix(), Reason: "scraper",
	}, now)
	// Overlay stats must not dump keys.
	st := ov.Stats()
	if st["ip"] != 1 {
		t.Fatalf("stats %+v", st)
	}
	if bytes.Contains(buf.Bytes(), []byte("198.51.100.7")) {
		t.Fatal("raw ip leaked to log buffer")
	}
}
