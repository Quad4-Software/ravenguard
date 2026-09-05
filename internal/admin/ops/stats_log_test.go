// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ops

import (
	"testing"
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
		Process: ProcessStats{
			CPUPercent: 12.34,
			RSSBytes:   64 * 1024 * 1024,
			Goroutines: 90,
		},
	}
	attrs := StatsLogAttrs(st)
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
	attrs := StatsLogAttrs(Status{})
	for i := 0; i+1 < len(attrs); i += 2 {
		if attrs[i] == "upstream_ok" {
			t.Fatal("upstream_ok should be omitted when unknown")
		}
	}
}
