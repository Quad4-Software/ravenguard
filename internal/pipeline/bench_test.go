// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package pipeline_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/detect"
	"github.com/Quad4-Software/ravenguard/internal/pipeline"
	"github.com/Quad4-Software/ravenguard/internal/privacy"
	"github.com/Quad4-Software/ravenguard/internal/protect"
	"github.com/Quad4-Software/ravenguard/internal/ratelimit"
	"github.com/Quad4-Software/ravenguard/internal/ui"
)

func BenchmarkGuardAllow(b *testing.B) {
	cfg := config.Default()
	cfg.Challenge.Secret = "bench-secret"
	cfg.Challenge.Enabled = false
	cfg.Detect.Enabled = true
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.Requests = 10_000_000
	cfg.RateLimit.Burst = 10_000_000
	cfg.Protect.Enabled = true
	cfg.Privacy.HashClientIP = false
	cfg.Privacy.LogIP = "off"
	cfg.UI.TestMode = false

	root := filepath.Join("..", "..")
	lists := blocklist.New()
	_ = lists.Load(
		[]string{filepath.Join(root, "testdata/blocklists/ips.txt")},
		[]string{filepath.Join(root, "testdata/blocklists/domains.txt")},
		[]string{filepath.Join(root, "testdata/blocklists/ua.txt")},
	)
	pages, err := ui.New(ui.Site{Brand: "Bench", Prefix: cfg.Challenge.PathPrefix})
	if err != nil {
		b.Fatal(err)
	}
	limiter := ratelimit.New(cfg.RateLimit.Requests, cfg.RateLimit.Burst, time.Minute, false)
	prot := protect.New(protect.Config{Enabled: true})
	beh := detect.NewBehaviorTracker(detect.BehaviorConfig{})
	priv := privacy.New(privacy.Config{HashClientIP: false, LogIP: "off", Secret: []byte("x")})
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := pipeline.New(cfg, lists, nil, limiter, nil, pages, upstream, nil, nil, nil, priv, beh, prot)

	req := httptest.NewRequest(http.MethodGet, "/products/shoes", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.RemoteAddr = "192.0.2.10:1234"
	rr := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		h.ServeHTTP(rr, req)
	}
}

func BenchmarkGuardAllowParallel(b *testing.B) {
	cfg := config.Default()
	cfg.Challenge.Secret = "bench-secret"
	cfg.Challenge.Enabled = false
	cfg.Detect.Enabled = true
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.Requests = 10_000_000
	cfg.RateLimit.Burst = 10_000_000
	cfg.Protect.Enabled = true
	cfg.Privacy.HashClientIP = false
	cfg.Privacy.LogIP = "off"
	cfg.UI.TestMode = false

	root := filepath.Join("..", "..")
	lists := blocklist.New()
	_ = lists.Load(
		[]string{filepath.Join(root, "testdata/blocklists/ips.txt")},
		[]string{filepath.Join(root, "testdata/blocklists/domains.txt")},
		[]string{filepath.Join(root, "testdata/blocklists/ua.txt")},
	)
	pages, err := ui.New(ui.Site{Brand: "Bench", Prefix: cfg.Challenge.PathPrefix})
	if err != nil {
		b.Fatal(err)
	}
	limiter := ratelimit.New(cfg.RateLimit.Requests, cfg.RateLimit.Burst, time.Minute, false)
	prot := protect.New(protect.Config{
		Enabled:             true,
		MaxConcurrentGlobal: 100_000,
		MaxConcurrentClient: 10_000,
	})
	beh := detect.NewBehaviorTracker(detect.BehaviorConfig{BurstLimit: 10_000_000})
	priv := privacy.New(privacy.Config{HashClientIP: false, LogIP: "off", Secret: []byte("x")})
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := pipeline.New(cfg, lists, nil, limiter, nil, pages, upstream, nil, nil, nil, priv, beh, prot)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/products/shoes", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Accept-Language", "en-US")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.RemoteAddr = "192.0.2.10:1234"
		for pb.Next() {
			h.ServeHTTP(rr, req)
		}
	})
}
