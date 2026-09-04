// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package pipeline_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/challenge"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/detect"
	"github.com/Quad4-Software/ravenguard/internal/iputil"
	"github.com/Quad4-Software/ravenguard/internal/pipeline"
	"github.com/Quad4-Software/ravenguard/internal/ui"
)

func spamTestHandler(t *testing.T, mutate func(*config.Config), beh *detect.BehaviorTracker) http.Handler {
	t.Helper()
	cfg := config.Default()
	cfg.Challenge.Secret = testSecret
	cfg.Challenge.Difficulty = 8
	cfg.Detect.ChallengeScore = 40
	cfg.Detect.BlockScore = 90
	cfg.RateLimit.Enabled = false
	cfg.Trust.Mode = "edge"
	cfg.Privacy.HashClientIP = false
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
	trusted, _ := iputil.ParseCIDRs(cfg.Trust.TrustedProxies)
	return pipeline.New(cfg, lists, nil, nil, chal, pages, upstream, trusted, nil, nil, testPriv(cfg), beh, nil)
}

func TestBlockAIAgentUA(t *testing.T) {
	h := spamTestHandler(t, nil, nil)
	for _, ua := range []string{
		"Mozilla/5.0 AppleWebKit/537.36 (compatible; GPTBot/1.2)",
		"Claude-User/1.0",
		"ChatGPT-Atlas/1.0",
		"DeepSeekBot/1.0",
		"xrumer",
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "text/html")
		req.RemoteAddr = "192.0.2.120:1"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			t.Fatalf("ua=%q should be blocked got %d", ua, rr.Code)
		}
	}
}

func TestForumSpamPOSTChallenges(t *testing.T) {
	h := spamTestHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "detect"
	}, nil)
	req := httptest.NewRequest(http.MethodPost, "/forum/reply", strings.NewReader("body=buy+viagra"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html")
	req.RemoteAddr = "192.0.2.121:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("spoofed browser forum post without form context must not reach origin")
	}
	body := rr.Body.String()
	if !strings.Contains(body, "rg-check") && !strings.Contains(body, "challenge") && rr.Code != http.StatusForbidden {
		t.Fatalf("expected challenge or block code=%d body=%s", rr.Code, body[:min(200, len(body))])
	}
}

func TestLegitimateForumPOSTPasses(t *testing.T) {
	h := spamTestHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "detect"
		cfg.Detect.Enabled = true
	}, nil)
	req := httptest.NewRequest(http.MethodPost, "/forum/reply", strings.NewReader("body=hello"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", "https://forum.example")
	req.Header.Set("Referer", "https://forum.example/topic/1")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.RemoteAddr = "192.0.2.122:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("legitimate post should pass code=%d body=%s", rr.Code, rr.Body.String()[:min(200, rr.Body.Len())])
	}
}

func TestWriteBurstChallengesSpammer(t *testing.T) {
	beh := detect.NewBehaviorTracker(detect.BehaviorConfig{
		Window:           time.Minute,
		BurstLimit:       1000,
		PathFanout:       1000,
		WriteBurstLimit:  5,
		WriteBurstScore:  50,
		WriteRepeatLimit: 5,
		WriteRepeatScore: 50,
	})
	h := spamTestHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "detect"
		cfg.Detect.EmptyFormContextScore = 0
		cfg.Detect.ForumWritePathScore = 0
		cfg.Detect.MissingAcceptLangScore = 0
		cfg.Detect.MissingSecFetchScore = 0
	}, beh)

	for i := range 5 {
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("u=bot"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Accept-Language", "en-US")
		req.Header.Set("Origin", "https://forum.example")
		req.Header.Set("Referer", "https://forum.example/register")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.RemoteAddr = "192.0.2.123:1"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if i < 4 {
			if rr.Code != http.StatusOK {
				t.Fatalf("post %d should pass before write burst code=%d", i, rr.Code)
			}
			continue
		}
		if rr.Code == http.StatusOK {
			t.Fatal("fifth repeated register POST should challenge or block")
		}
	}
}

func TestLegitimateJSONAPIPasses(t *testing.T) {
	h := spamTestHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "detect"
	}, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orders", strings.NewReader(`{"sku":"a"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Origin", "https://shop.example")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.RemoteAddr = "192.0.2.125:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("general JSON API should pass code=%d body=%s", rr.Code, rr.Body.String()[:min(200, rr.Body.Len())])
	}
}

func TestSearchCrawlersNotHardBlocked(t *testing.T) {
	h := spamTestHandler(t, func(cfg *config.Config) {
		cfg.Detect.Enabled = false
		cfg.Challenge.Enabled = false
	}, nil)
	for _, ua := range []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)",
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "text/html")
		req.RemoteAddr = "192.0.2.124:1"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("search crawler %q must not hard-block code=%d", ua, rr.Code)
		}
	}
}
