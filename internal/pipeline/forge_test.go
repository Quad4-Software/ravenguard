// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package pipeline_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/allowlist"
	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/challenge"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/pipeline"
	"github.com/Quad4-Software/ravenguard/internal/ui"
)

func forgeBrowserHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
}

func forgeTestHandler(t *testing.T, mutate func(*config.Config)) http.Handler {
	t.Helper()
	return spamTestHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "detect"
		cfg.Detect.Enabled = true
		cfg.Detect.ForgeExpensiveScore = 40
		cfg.Detect.ChallengeScore = 40
		cfg.Detect.BlockScore = 90
		cfg.Detect.MissingUAScore = 0
		cfg.Detect.MissingAcceptScore = 0
		cfg.Detect.MissingAcceptLangScore = 0
		cfg.Detect.MissingSecFetchScore = 0
		cfg.Detect.SecCHUAMismatchScore = 0
		cfg.Detect.StarAcceptBrowserScore = 0
		cfg.Detect.ScannerUAScore = 0
		cfg.Detect.AIUAScore = 0
		cfg.Detect.ProbePathScore = 0
		if mutate != nil {
			mutate(cfg)
		}
	}, nil)
}

func TestForgeNormalBrowsingPasses(t *testing.T) {
	h := forgeTestHandler(t, nil)
	paths := []string{
		"/owner/repo",
		"/owner/repo/src/branch/main",
		"/owner/repo/issues",
		"/owner/repo/commits/branch/main",
		"/owner/repo.git/info/refs",
	}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		forgeBrowserHeaders(req)
		req.RemoteAddr = "192.0.2.200:1"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("path=%q should pass code=%d body=%s", p, rr.Code, rr.Body.String()[:min(200, rr.Body.Len())])
		}
	}
}

func TestForgeHotPathChallenges(t *testing.T) {
	h := forgeTestHandler(t, nil)
	for _, p := range []string{
		"/owner/repo/compare/a...b",
		"/owner/repo/blame/branch/f.go",
		"/owner/repo/archive/main.zip",
	} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		forgeBrowserHeaders(req)
		req.RemoteAddr = "192.0.2.201:1"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			t.Fatalf("path=%q should challenge", p)
		}
		body := rr.Body.String()
		if !strings.Contains(body, "rg-check") && rr.Code != http.StatusForbidden {
			t.Fatalf("path=%q expected challenge code=%d body=%s", p, rr.Code, body[:min(200, len(body))])
		}
	}
}

func TestForgeHotClearancePasses(t *testing.T) {
	h := forgeTestHandler(t, func(cfg *config.Config) {
		cfg.Privacy.HashClientIP = false
	})
	bindID := "192.0.2.202"
	m := &challenge.Manager{Secret: []byte(testSecret), Difficulty: 8, CookieName: "rg_clear", CookieTTL: time.Hour, Algorithm: "sha256"}
	raw := solvedPayload(t, m, bindID, challenge.GateInteractive, challenge.EnvAttestation{Interacted: true, SolveMs: 200})
	payloadJSON, _ := json.Marshal(map[string]any{"payload": raw})
	creq := httptest.NewRequest(http.MethodPost, "/_rg/challenge", bytes.NewReader(payloadJSON))
	creq.Header.Set("Content-Type", "application/json")
	creq.RemoteAddr = "192.0.2.202:1"
	crr := httptest.NewRecorder()
	h.ServeHTTP(crr, creq)
	if crr.Code != http.StatusOK {
		t.Fatalf("challenge post=%d %s", crr.Code, crr.Body.String())
	}
	cookies := crr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected clearance cookie")
	}

	req := httptest.NewRequest(http.MethodGet, "/owner/repo/compare/a...b", nil)
	forgeBrowserHeaders(req)
	req.RemoteAddr = "192.0.2.202:1"
	req.AddCookie(cookies[0])
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("cleared hot path should pass code=%d", rr.Code)
	}
}

func TestForgeHotAllowlistPasses(t *testing.T) {
	dir := t.TempDir()
	ipFile := filepath.Join(dir, "ips.txt")
	if err := os.WriteFile(ipFile, []byte("192.0.2.203\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	allows := allowlist.New()
	if err := allows.Load([]string{ipFile}, nil, nil); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Challenge.Secret = testSecret
	cfg.Challenge.Difficulty = 8
	cfg.Challenge.Mode = "detect"
	cfg.Detect.ForgeExpensiveScore = 40
	cfg.Detect.ChallengeScore = 40
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
		CookieTTL:  time.Hour,
	}
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	h := pipeline.New(cfg, blocklist.New(), nil, nil, chal, pages, upstream, nil, nil, nil, testPriv(cfg), nil, nil)
	h.SetAllowlists(allows)

	req := httptest.NewRequest(http.MethodGet, "/owner/repo/compare/a...b", nil)
	forgeBrowserHeaders(req)
	req.RemoteAddr = "192.0.2.203:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("allowlisted hot path should pass code=%d", rr.Code)
	}
}
