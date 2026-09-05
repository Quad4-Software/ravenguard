// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ops

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/requestlog"
)

func TestStatsLogAttrs(t *testing.T) {
	t.Parallel()
	up := true
	st := Status{
		UptimeSeconds:      42,
		BanCount:           3,
		ConcurrencyGlobal:  7,
		ConcurrencyClients: 2,
		RateLimitBuckets:   11,
		ChallengeEnabled:   true,
		DetectEnabled:      true,
		UpstreamHealthy:    &up,
		Blocklists: blocklist.Stats{
			IPCount:  100,
			DNSCount: 20,
			UACount:  5,
		},
		Process: ProcessStats{
			CPUPercent: 12.34,
			RSSBytes:   64 * 1024 * 1024,
			Goroutines: 90,
		},
	}
	iv := requestlog.Counters{Challenges: 12, Blocks: 2, RateLimits: 1}
	total := requestlog.Counters{Challenges: 400, Blocks: 50, RateLimits: 9}
	attrs := StatsLogAttrs(st, iv, total)
	m := map[string]any{}
	for i := 0; i+1 < len(attrs); i += 2 {
		k, ok := attrs[i].(string)
		if !ok {
			t.Fatalf("attr key %v", attrs[i])
		}
		m[k] = attrs[i+1]
	}
	if m["uptime_s"] != int64(42) {
		t.Fatalf("uptime=%v", m["uptime_s"])
	}
	if m["bans"] != 3 {
		t.Fatalf("bans=%v", m["bans"])
	}
	if m["challenges"] != uint64(12) {
		t.Fatalf("challenges=%v", m["challenges"])
	}
	if m["blocks"] != uint64(2) {
		t.Fatalf("blocks=%v", m["blocks"])
	}
	if m["challenges_total"] != uint64(400) {
		t.Fatalf("challenges_total=%v", m["challenges_total"])
	}
	if m["blocklist_ips"] != 100 {
		t.Fatalf("blocklist_ips=%v", m["blocklist_ips"])
	}
	if m["upstream_ok"] != true {
		t.Fatalf("upstream=%v", m["upstream_ok"])
	}
	if m["rss_mb"] != uint64(64) {
		t.Fatalf("rss=%v", m["rss_mb"])
	}
	if m["cpu_pct"] != 12.3 {
		t.Fatalf("cpu=%v", m["cpu_pct"])
	}
}

func TestStatsLogAttrsOmitsUpstreamWhenNil(t *testing.T) {
	t.Parallel()
	attrs := StatsLogAttrs(Status{}, requestlog.Counters{}, requestlog.Counters{})
	for i := 0; i+1 < len(attrs); i += 2 {
		if attrs[i] == "upstream_ok" {
			t.Fatal("upstream_ok should be omitted when unknown")
		}
		if attrs[i] == "waf_other" {
			t.Fatal("waf_other should be omitted when zero")
		}
	}
}

func TestStatsLogAttrsIncludesWAFOther(t *testing.T) {
	t.Parallel()
	iv := requestlog.Counters{Coraza: 3, ML: 1}
	total := requestlog.Counters{Coraza: 10, ML: 4}
	attrs := StatsLogAttrs(Status{}, iv, total)
	m := map[string]any{}
	for i := 0; i+1 < len(attrs); i += 2 {
		k, ok := attrs[i].(string)
		if !ok {
			t.Fatalf("attr key %v", attrs[i])
		}
		m[k] = attrs[i+1]
	}
	if m["waf_other"] != uint64(4) {
		t.Fatalf("waf_other=%v", m["waf_other"])
	}
	if m["waf_other_total"] != uint64(14) {
		t.Fatalf("waf_other_total=%v", m["waf_other_total"])
	}
}
