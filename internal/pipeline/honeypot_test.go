// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package pipeline_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/pipeline"
	"github.com/Quad4-Software/ravenguard/internal/protect"
	"github.com/Quad4-Software/ravenguard/internal/ui"
)

func trapHandler(t *testing.T, action string) (http.Handler, *protect.Guard) {
	t.Helper()
	cfg := config.Default()
	cfg.Challenge.Secret = testSecret
	cfg.Challenge.Enabled = false
	cfg.Detect.Enabled = false
	cfg.RateLimit.Enabled = false
	cfg.Privacy.HashClientIP = false
	cfg.Honeypot.Enabled = true
	cfg.Honeypot.Paths = []string{"/.git/config", "/trap-door"}
	cfg.Honeypot.Prefixes = []string{"/wp-admin"}
	cfg.Honeypot.Action = action
	cfg.Honeypot.BanTTL = config.Duration{Duration: time.Minute}
	cfg.Tarpit.Interval = config.Duration{Duration: 5 * time.Millisecond}
	cfg.Tarpit.BytesPerTick = 16
	cfg.Tarpit.MaxDuration = config.Duration{Duration: 25 * time.Millisecond}
	pages, _ := ui.New(ui.Site{Brand: "RavenGuard", StatusText: "x", Prefix: "/_rg"})
	prot := protect.New(protect.Config{Enabled: true, BanTTL: time.Minute})
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})
	h := pipeline.New(cfg, blocklist.New(), nil, nil, nil, pages, upstream, nil, nil, nil, testPriv(cfg), nil, prot)
	return h, prot
}

func TestHoneypotBan(t *testing.T) {
	h, prot := trapHandler(t, "ban")
	req := httptest.NewRequest(http.MethodGet, "/.git/config", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.RemoteAddr = "198.51.100.7:7777"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rr.Code)
	}
	if !prot.Banned("198.51.100.7") {
		t.Fatal("trap hit should ban the client")
	}
	// A second request is denied by the active ban even on a clean path.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.7:7777"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("banned client should stay denied, code=%d", rr.Code)
	}
}

func TestHoneypotPrefixAndCleanPath(t *testing.T) {
	h, _ := trapHandler(t, "deny")
	req := httptest.NewRequest(http.MethodGet, "/wp-admin/setup.php", nil)
	req.RemoteAddr = "198.51.100.8:7777"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("prefix trap code=%d", rr.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.9:7777"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("clean path code=%d", rr.Code)
	}
}

func TestHoneypotCaseInsensitive(t *testing.T) {
	h, _ := trapHandler(t, "deny")
	req := httptest.NewRequest(http.MethodGet, "/TRAP-DOOR", nil)
	req.RemoteAddr = "198.51.100.10:7777"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("case variant should trap, code=%d", rr.Code)
	}
}

func TestHoneypotTarpit(t *testing.T) {
	h, _ := trapHandler(t, "tarpit")
	req := httptest.NewRequest(http.MethodGet, "/trap-door", nil)
	req.RemoteAddr = "198.51.100.11:7777"
	rr := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("tarpit code=%d", rr.Code)
	}
	if time.Since(start) < 20*time.Millisecond {
		t.Fatal("tarpit returned before the drip finished")
	}
}

func TestDecisionsEndpoint(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = testSecret
	cfg.Challenge.Enabled = false
	cfg.Detect.Enabled = false
	cfg.RateLimit.Enabled = false
	cfg.Privacy.HashClientIP = false
	cfg.Decisions.Enabled = true
	cfg.Decisions.Token = "bouncer-secret"
	pages, _ := ui.New(ui.Site{Brand: "RavenGuard", StatusText: "x", Prefix: "/_rg"})
	prot := protect.New(protect.Config{Enabled: true, BanTTL: time.Minute})
	prot.BanUntil("203.0.113.66", time.Now().Add(time.Minute))
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := pipeline.New(cfg, blocklist.New(), nil, nil, nil, pages, upstream, nil, nil, nil, testPriv(cfg), nil, prot)

	// Disabled path shape check: no token.
	req := httptest.NewRequest(http.MethodGet, "/_rg/decisions", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated code=%d", rr.Code)
	}

	// Wrong token.
	req = httptest.NewRequest(http.MethodGet, "/_rg/decisions", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad token code=%d", rr.Code)
	}

	// Right token returns the active ban.
	req = httptest.NewRequest(http.MethodGet, "/_rg/decisions", nil)
	req.Header.Set("Authorization", "Bearer bouncer-secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("decisions code=%d", rr.Code)
	}
	var out struct {
		Decisions []struct {
			Value string `json:"value"`
			Type  string `json:"type"`
			Until string `json:"until"`
		} `json:"decisions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Decisions) != 1 || out.Decisions[0].Value != "203.0.113.66" {
		t.Fatalf("decisions=%+v", out.Decisions)
	}
}

func TestDecisionsDisabled(t *testing.T) {
	h := testHandler(t, func(c *config.Config) {
		c.Decisions.Enabled = false
	})
	req := httptest.NewRequest(http.MethodGet, "/_rg/decisions", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("disabled code=%d", rr.Code)
	}
}
