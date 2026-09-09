// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package pipeline_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/challenge"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/pipeline"
	"github.com/Quad4-Software/ravenguard/internal/router"
	"github.com/Quad4-Software/ravenguard/internal/ui"
)

func TestChallengeSkipPathPrefixesConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = testSecret
	cfg.Challenge.Difficulty = 8
	cfg.Challenge.Mode = "always"
	cfg.Challenge.SkipPathPrefixes = []string{"/xmpp-websocket", "/http-bind"}
	cfg.Detect.Enabled = false
	cfg.RateLimit.Enabled = false
	cfg.Trust.Mode = "edge"
	cfg.Privacy.HashClientIP = false

	pages, err := ui.New(ui.SiteFromConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	chal := &challenge.Manager{
		Secret:     []byte(cfg.Challenge.Secret),
		Difficulty: cfg.Challenge.Difficulty,
		Algorithm:  "sha256",
		CookieName: cfg.Challenge.CookieName,
		CookieTTL:  cfg.Challenge.CookieTTL.Duration,
	}
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := pipeline.New(cfg, blocklist.New(), nil, nil, chal, pages, upstream, nil, nil, nil, testPriv(cfg), nil, nil)

	// WebSocket upgrade under a skipped prefix reaches the origin without clearance.
	wsReq := wsUpgradeRequest("/xmpp-websocket", "192.0.2.70:1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, wsReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("skipped ws code=%d body=%s", rr.Code, rr.Body.String())
	}

	// Regular GET under a skipped prefix reaches the origin without challenge.
	getReq := httptest.NewRequest(http.MethodGet, "/http-bind", nil)
	getReq.Header.Set("User-Agent", "Mozilla/5.0")
	getReq.Header.Set("Accept", "text/html")
	getReq.RemoteAddr = "192.0.2.71:1"
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, getReq)
	if rr2.Code != http.StatusOK {
		t.Fatalf("skipped get code=%d body=%s", rr2.Code, rr2.Body.String())
	}

	// A non-skipped path still receives a challenge in always mode.
	other := httptest.NewRequest(http.MethodGet, "/", nil)
	other.Header.Set("User-Agent", "Mozilla/5.0")
	other.Header.Set("Accept", "text/html")
	other.RemoteAddr = "192.0.2.72:1"
	rr3 := httptest.NewRecorder()
	h.ServeHTTP(rr3, other)
	if rr3.Code == http.StatusOK {
		t.Fatalf("non-skipped path should not pass in always mode")
	}
	body := rr3.Body.String()
	if !strings.Contains(body, "rg-check") && !strings.Contains(body, "challenge") {
		t.Fatalf("expected challenge page for non-skipped path code=%d body=%s", rr3.Code, body)
	}
}

func TestChallengeSkipRoute(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = testSecret
	cfg.Challenge.Difficulty = 8
	cfg.Challenge.Mode = "always"
	cfg.Detect.Enabled = false
	cfg.RateLimit.Enabled = false
	cfg.Trust.Mode = "edge"
	cfg.Privacy.HashClientIP = false

	pages, err := ui.New(ui.SiteFromConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	chal := &challenge.Manager{
		Secret:     []byte(cfg.Challenge.Secret),
		Difficulty: cfg.Challenge.Difficulty,
		Algorithm:  "sha256",
		CookieName: cfg.Challenge.CookieName,
		CookieTTL:  cfg.Challenge.CookieTTL.Duration,
	}
	var upstreamPath string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	h := pipeline.New(cfg, blocklist.New(), nil, nil, chal, pages, upstream, nil, nil, nil, testPriv(cfg), nil, nil)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(origin.Close)

	rt := router.New(t.Context())
	if err := rt.Replace(
		[]router.Upstream{{ID: "u1", Name: "ws", URL: origin.URL}},
		[]router.Route{
			{ID: "r1", Name: "ws", Enabled: true, Hosts: []string{}, PathPrefix: "/xmpp-websocket", UpstreamID: "u1", SkipChallenge: true},
			{ID: "r2", Name: "other", Enabled: true, Hosts: []string{}, PathPrefix: "/", UpstreamID: "u1"},
		},
	); err != nil {
		t.Fatal(err)
	}
	h.SetRouter(rt)

	wsReq := wsUpgradeRequest("/xmpp-websocket", "192.0.2.73:1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, wsReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("route-skipped ws code=%d body=%s", rr.Code, rr.Body.String())
	}
	if upstreamPath != "/xmpp-websocket" {
		t.Fatalf("unexpected upstream path %q", upstreamPath)
	}

	// Other routes still require clearance in always mode.
	other := httptest.NewRequest(http.MethodGet, "/", nil)
	other.Header.Set("User-Agent", "Mozilla/5.0")
	other.Header.Set("Accept", "text/html")
	other.RemoteAddr = "192.0.2.74:1"
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, other)
	if rr2.Code == http.StatusOK {
		t.Fatalf("non-skipped route should still challenge")
	}
}
