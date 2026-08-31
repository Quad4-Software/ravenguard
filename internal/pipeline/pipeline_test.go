// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package pipeline_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/challenge"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/detect"
	"github.com/Quad4-Software/ravenguard/internal/pipeline"
	"github.com/Quad4-Software/ravenguard/internal/privacy"
	"github.com/Quad4-Software/ravenguard/internal/protect"
	"github.com/Quad4-Software/ravenguard/internal/ratelimit"
	"github.com/Quad4-Software/ravenguard/internal/ui"
)

const testSecret = "integration-secret"

func testPriv(cfg config.Config) *privacy.Guard {
	sec := cfg.Privacy.IPHashSecret
	if sec == "" {
		sec = cfg.Challenge.Secret
	}
	return privacy.New(privacy.Config{
		HashClientIP: cfg.Privacy.HashClientIP,
		Secret:       []byte(sec),
		LogIP:        cfg.Privacy.LogIP,
	})
}

func testHandler(t *testing.T, mutate func(*config.Config)) http.Handler {
	t.Helper()
	cfg := config.Default()
	cfg.Challenge.Secret = testSecret
	cfg.Challenge.Difficulty = 8
	cfg.Detect.ChallengeScore = 40
	cfg.Detect.BlockScore = 90
	cfg.RateLimit.Enabled = false
	cfg.Trust.Mode = "edge"
	if mutate != nil {
		mutate(&cfg)
	}
	root := filepath.Join("..", "..")
	lists := blocklist.New()
	_ = lists.Load(
		[]string{filepath.Join(root, "testdata/blocklists/ips.txt")},
		[]string{filepath.Join(root, "testdata/blocklists/domains.txt")},
		[]string{filepath.Join(root, "testdata/blocklists/ua.txt")},
	)
	pages, err := ui.New(ui.Site{
		Brand:            cfg.UI.Brand,
		StatusText:       cfg.UI.StatusText,
		Prefix:           cfg.Challenge.PathPrefix,
		PrivacyNoticeURL: cfg.Privacy.PrivacyNoticeURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	chal := &challenge.Manager{
		Secret:     []byte(cfg.Challenge.Secret),
		Difficulty: cfg.Challenge.Difficulty,
		CookieName: cfg.Challenge.CookieName,
		CookieTTL:  time.Hour,
	}
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return pipeline.New(cfg, lists, nil, nil, chal, pages, upstream, nil, nil, nil, testPriv(cfg), nil, nil)
}

func TestAllowCleanRequest(t *testing.T) {
	h := testHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.RemoteAddr = "192.0.2.10:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "ok" {
		t.Fatalf("body=%q", rr.Body.String())
	}
	if rr.Header().Get("X-RavenGuard-Ray") == "" {
		t.Fatal("missing ray")
	}
}

func TestBlockIP(t *testing.T) {
	h := testHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.RemoteAddr = "203.0.113.10:9999"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rr.Code)
	}
}

func TestBlockUA(t *testing.T) {
	h := testHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "sqlmap/1.0")
	req.Header.Set("Accept", "*/*")
	req.RemoteAddr = "192.0.2.20:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rr.Code)
	}
}

func TestChallengeAndClearance(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Detect.BlockScore = 200
		cfg.Detect.ChallengeScore = 40
	})
	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	req.RemoteAddr = "192.0.2.30:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("challenge code=%d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "window.__RG__") {
		t.Fatalf("missing challenge page: %s", body[:min(200, len(body))])
	}

	priv := privacy.New(privacy.Config{
		HashClientIP: true,
		Secret:       []byte(testSecret),
		LogIP:        "hash",
	})
	bindID := priv.ClientKey("192.0.2.30")
	m := &challenge.Manager{Secret: []byte(testSecret), Difficulty: 8, CookieName: "rg_clear", CookieTTL: time.Hour}
	tok, payload, err := m.Issue(bindID)
	if err != nil {
		t.Fatal(err)
	}
	sol, err := challenge.SolvePoW(tok.Nonce, tok.Difficulty)
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, _ := json.Marshal(map[string]any{
		"token":    payload,
		"solution": strconv.FormatUint(sol, 10),
		"ray":      "test",
		"env": map[string]any{
			"webdriver":  false,
			"playwright": false,
			"headless":   false,
			"no_plugins": false,
			"interacted": true,
			"solve_ms":   200,
		},
	})
	creq := httptest.NewRequest(http.MethodPost, "/_rg/challenge", bytes.NewReader(payloadJSON))
	creq.Header.Set("Content-Type", "application/json")
	creq.RemoteAddr = "192.0.2.30:1"
	crr := httptest.NewRecorder()
	h.ServeHTTP(crr, creq)
	if crr.Code != http.StatusOK {
		t.Fatalf("challenge post=%d %s", crr.Code, crr.Body.String())
	}
	cookies := crr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected cookie")
	}

	replay := httptest.NewRequest(http.MethodPost, "/_rg/challenge", bytes.NewReader(payloadJSON))
	replay.Header.Set("Content-Type", "application/json")
	replay.RemoteAddr = "192.0.2.30:1"
	rrr := httptest.NewRecorder()
	h.ServeHTTP(rrr, replay)
	if rrr.Code == http.StatusOK {
		t.Fatal("expected replay rejection")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/.env", nil)
	req2.Header.Set("User-Agent", "curl/8.0")
	req2.RemoteAddr = "192.0.2.30:1"
	req2.AddCookie(cookies[0])
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("cleared code=%d body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestWebdriverEnvRefused(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "always"
		cfg.Detect.Enabled = false
		cfg.Privacy.HashClientIP = false
	})
	bindID := "192.0.2.88"
	m := &challenge.Manager{Secret: []byte(testSecret), Difficulty: 8, CookieName: "rg_clear", CookieTTL: time.Hour}
	tok, payload, err := m.Issue(bindID)
	if err != nil {
		t.Fatal(err)
	}
	sol, err := challenge.SolvePoW(tok.Nonce, tok.Difficulty)
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, _ := json.Marshal(map[string]any{
		"token":    payload,
		"solution": strconv.FormatUint(sol, 10),
		"env": map[string]any{
			"webdriver":  true,
			"playwright": false,
			"headless":   false,
			"no_plugins": true,
			"interacted": true,
			"solve_ms":   200,
		},
	})
	creq := httptest.NewRequest(http.MethodPost, "/_rg/challenge", bytes.NewReader(payloadJSON))
	creq.Header.Set("Content-Type", "application/json")
	creq.RemoteAddr = "192.0.2.88:1"
	crr := httptest.NewRecorder()
	h.ServeHTTP(crr, creq)
	if crr.Code == http.StatusOK {
		t.Fatal("expected webdriver refusal")
	}
	if !strings.Contains(crr.Body.String(), "webdriver") {
		t.Fatalf("body=%q", crr.Body.String())
	}
}

func TestChallengeSecureFromProto(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "always"
		cfg.Detect.Enabled = false
		cfg.Privacy.HashClientIP = false
	})
	priv := privacy.New(privacy.Config{HashClientIP: false, Secret: []byte(testSecret), LogIP: "off"})
	bindID := priv.ClientKey("192.0.2.77")
	m := &challenge.Manager{Secret: []byte(testSecret), Difficulty: 8, CookieName: "rg_clear", CookieTTL: time.Hour}
	tok, payload, err := m.Issue(bindID)
	if err != nil {
		t.Fatal(err)
	}
	sol, err := challenge.SolvePoW(tok.Nonce, tok.Difficulty)
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, _ := json.Marshal(map[string]any{
		"token":    payload,
		"solution": strconv.FormatUint(sol, 10),
		"env": map[string]any{
			"webdriver":  false,
			"playwright": false,
			"headless":   false,
			"no_plugins": false,
			"interacted": true,
			"solve_ms":   200,
		},
	})
	creq := httptest.NewRequest(http.MethodPost, "/_rg/challenge", bytes.NewReader(payloadJSON))
	creq.Header.Set("Content-Type", "application/json")
	creq.Header.Set("X-Forwarded-Proto", "https")
	creq.RemoteAddr = "192.0.2.77:1"
	crr := httptest.NewRecorder()
	h.ServeHTTP(crr, creq)
	if crr.Code != http.StatusOK {
		t.Fatalf("post=%d %s", crr.Code, crr.Body.String())
	}
	cookies := crr.Result().Cookies()
	if len(cookies) == 0 || !cookies[0].Secure {
		t.Fatalf("expected secure cookie got %#v", cookies)
	}
}

func TestChallengeAlways(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "always"
		cfg.Detect.Enabled = false
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.RemoteAddr = "192.0.2.50:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "window.__RG__") {
		t.Fatal("expected challenge page")
	}
}

func wsUpgradeRequest(path, remote string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.RemoteAddr = remote
	return req
}

func TestWebSocketRequiresClearance(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Detect.Enabled = false
	})
	req := wsUpgradeRequest("/ws", "192.0.2.40:1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "clearance required") {
		t.Fatalf("body=%q", rr.Body.String())
	}
}

func TestWebSocketWithClearance(t *testing.T) {
	var sawUpgrade string
	cfg := config.Default()
	cfg.Challenge.Secret = testSecret
	cfg.Challenge.Difficulty = 8
	cfg.Detect.Enabled = false
	cfg.RateLimit.Enabled = false
	cfg.Trust.Mode = "edge"
	cfg.Privacy.HashClientIP = false
	root := filepath.Join("..", "..")
	lists := blocklist.New()
	_ = lists.Load(
		[]string{filepath.Join(root, "testdata/blocklists/ips.txt")},
		[]string{filepath.Join(root, "testdata/blocklists/domains.txt")},
		[]string{filepath.Join(root, "testdata/blocklists/ua.txt")},
	)
	pages, err := ui.New(ui.Site{
		Brand:      cfg.UI.Brand,
		StatusText: cfg.UI.StatusText,
		Prefix:     cfg.Challenge.PathPrefix,
	})
	if err != nil {
		t.Fatal(err)
	}
	chal := &challenge.Manager{
		Secret:     []byte(cfg.Challenge.Secret),
		Difficulty: cfg.Challenge.Difficulty,
		CookieName: cfg.Challenge.CookieName,
		CookieTTL:  time.Hour,
	}
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawUpgrade = r.Header.Get("Upgrade")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ws-ok"))
	})
	h := pipeline.New(cfg, lists, nil, nil, chal, pages, upstream, nil, nil, nil, testPriv(cfg), nil, nil)

	bindID := "192.0.2.41"
	cookie := chal.ClearanceCookie(bindID, "ray-ws", false)
	req := wsUpgradeRequest("/ws", "192.0.2.41:1")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if sawUpgrade != "websocket" {
		t.Fatalf("upgrade=%q", sawUpgrade)
	}
	if rr.Body.String() != "ws-ok" {
		t.Fatalf("body=%q", rr.Body.String())
	}
}

func TestWebSocketChallengeDisabled(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Enabled = false
		cfg.Detect.Enabled = false
	})
	req := wsUpgradeRequest("/ws", "192.0.2.42:1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "ok" {
		t.Fatalf("body=%q", rr.Body.String())
	}
}

func TestHigh404Block(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Enabled = false
	cfg.Challenge.Secret = testSecret
	cfg.Detect.Enabled = true
	cfg.Detect.ChallengeScore = 999
	cfg.Detect.BlockScore = 999
	cfg.Detect.High404Threshold = 3
	cfg.Detect.High404Window = config.Duration{Duration: time.Minute}
	cfg.Detect.High404Action = "block"
	cfg.RateLimit.Enabled = false
	cfg.Privacy.HashClientIP = false
	pages, _ := ui.New(ui.Site{Brand: "RavenGuard", StatusText: "x", Prefix: "/_rg"})
	nf := detect.NewNotFoundTracker(3, time.Minute)
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("missing"))
	})
	h := pipeline.New(cfg, blocklist.New(), nil, nil, nil, pages, upstream, nil, nf, nil, testPriv(cfg), nil, nil)
	for i := range 3 {
		req := httptest.NewRequest(http.MethodGet, "/missing", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "text/html")
		req.RemoteAddr = "192.0.2.60:1"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("seed %d code=%d", i, rr.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.RemoteAddr = "192.0.2.60:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected block got %d", rr.Code)
	}
}

func TestTestModePages(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.UI.TestMode = true
	})
	paths := []struct {
		path string
		code int
		want string
	}{
		{"/_rg/test", 200, "UI preview"},
		{"/_rg/test/block", 403, "Access denied"},
		{"/_rg/test/ratelimit", 429, "Too many requests"},
		{"/_rg/test/upstream", 502, "Origin unreachable"},
		{"/_rg/test/error", 500, "Internal error"},
		{"/_rg/test/challenge", 403, "window.__RG__"},
	}
	for _, tc := range paths {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != tc.code {
			t.Fatalf("%s code=%d want %d body=%s", tc.path, rr.Code, tc.code, rr.Body.String()[:min(120, rr.Body.Len())])
		}
		if !strings.Contains(rr.Body.String(), tc.want) {
			t.Fatalf("%s missing %q", tc.path, tc.want)
		}
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/_rg/static/", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("static dir code=%d", rr.Code)
	}
	if rr.Header().Get("Location") != "/_rg/test" {
		t.Fatalf("location=%q", rr.Header().Get("Location"))
	}
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/_rg", nil))
	if rr2.Code != http.StatusFound || rr2.Header().Get("Location") != "/_rg/test" {
		t.Fatalf("/_rg redirect code=%d loc=%q", rr2.Code, rr2.Header().Get("Location"))
	}
}

func TestAttackBlocked(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = testSecret
	cfg.Challenge.Enabled = false
	cfg.Detect.Enabled = false
	cfg.RateLimit.Enabled = false
	cfg.Protect.Enabled = true
	cfg.Protect.AttackBlock = true
	cfg.Privacy.HashClientIP = false
	pages, _ := ui.New(ui.Site{Brand: "RavenGuard", StatusText: "x", Prefix: "/_rg"})
	prot := protect.New(protect.Config{
		Enabled:     true,
		AttackBlock: true,
		BanTTL:      time.Minute,
	})
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})
	h := pipeline.New(cfg, blocklist.New(), nil, nil, nil, pages, upstream, nil, nil, nil, testPriv(cfg), nil, prot)
	req := httptest.NewRequest(http.MethodGet, "/search?q=1'+union+select+1", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.RemoteAddr = "192.0.2.99:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if !prot.Banned("192.0.2.99") {
		t.Fatal("expected temp ban")
	}
}

func TestRateLimit(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = testSecret
	cfg.Challenge.Enabled = false
	cfg.Detect.Enabled = false
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.Requests = 1
	cfg.RateLimit.Burst = 1
	cfg.RateLimit.Window = config.Duration{Duration: time.Minute}
	cfg.RateLimit.ChallengeOver = false
	cfg.Privacy.HashClientIP = false
	pages, _ := ui.New(ui.Site{Brand: "RavenGuard", StatusText: "x", Prefix: "/_rg"})
	limiter := ratelimit.New(1, 1, time.Minute, false)
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})
	h := pipeline.New(cfg, blocklist.New(), nil, limiter, nil, pages, upstream, nil, nil, nil, testPriv(cfg), nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.40:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("first=%d", rr.Code)
	}
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second=%d", rr2.Code)
	}
}
