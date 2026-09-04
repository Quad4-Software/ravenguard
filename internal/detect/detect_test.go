// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/detect"
)

func testCfg() detect.Config {
	return detect.Config{
		MissingUAScore:         25,
		ScannerUAScore:         50,
		AIUAScore:              55,
		ProbePathScore:         40,
		OddMethodScore:         30,
		MissingAcceptScore:     10,
		MissingAcceptLangScore: 15,
		MissingSecFetchScore:   20,
		SecCHUAMismatchScore:   25,
		StarAcceptBrowserScore: 15,
		EmptyFormContextScore:  30,
		ForumWritePathScore:    25,
		ProxyBotLowScore:       40,
		ProxyBotHeader:         "CF-Bot-Score",
		ProxyBotScoreHeader:    "X-Bot-Score",
	}
}

func TestScannerUA(t *testing.T) {
	if !detect.IsScannerUA("sqlmap/1.7") {
		t.Fatal("expected scanner")
	}
	if detect.IsScannerUA("Mozilla/5.0 Chrome/120") {
		t.Fatal("unexpected")
	}
}

func TestAIUA(t *testing.T) {
	ais := []string{
		"Mozilla/5.0 AppleWebKit/537.36 (compatible; GPTBot/1.2)",
		"Mozilla/5.0 (compatible; ClaudeBot/1.0)",
		"Claude-User/1.0",
		"Claude-SearchBot/1.0",
		"Mozilla/5.0 AppleWebKit/537.36 (compatible; OAI-SearchBot/1.0)",
		"ChatGPT-User/1.0",
		"PerplexityBot/1.0",
		"Perplexity-User/1.0",
		"Bytespider",
		"CCBot/2.0",
		"Google-Extended",
		"Google-Agent",
		"Google-CloudVertexBot",
		"GoogleAgent-Mariner",
		"meta-externalagent",
		"meta-externalfetcher",
		"Applebot-Extended",
		"Amazonbot/0.1",
		"cohere-ai",
		"AI2Bot",
		"Diffbot",
		"YouBot",
		"ImagesiftBot",
		"MistralAI-User",
		"DuckAssistBot",
		"Timpibot/1.0",
		"PanguBot",
		"omgilibot",
		"webzio-extended",
		"ChatGPT-Atlas/1.0",
		"Claude-Code/2.1.0",
		"DeepSeekBot/1.0",
		"QwenBot",
		"iaskspider/2.0",
		"PhindBot",
		"NotebookLM",
		"Gemini-Deep-Research",
	}
	for _, ua := range ais {
		if !detect.IsAIUA(ua) {
			t.Fatalf("expected ai ua: %q", ua)
		}
		if !detect.IsScannerUA(ua) {
			t.Fatalf("ai should count as scanner-class: %q", ua)
		}
	}
	if detect.IsAIUA("Mozilla/5.0 (compatible; Googlebot/2.1)") {
		t.Fatal("Googlebot search must not score as AI UA")
	}
	if detect.IsAIUA("Mozilla/5.0 (compatible; Applebot/0.1)") {
		t.Fatal("Applebot search must not score as AI UA")
	}
}

func TestScannerUALibraries(t *testing.T) {
	scanners := []string{
		"sqlmap/1.7",
		"python-requests/2.31.0",
		"aiohttp/3.9.0",
		"axios/1.6.0",
		"node-fetch/3.0",
		"undici",
		"puppeteer",
		"playwright",
		"HeadlessChrome/120",
		"crawl4ai",
		"firecrawl",
		"browser-use",
		"scrapy/2.11",
		"PostmanRuntime/7.36",
		"xrumer",
		"Scrapebox",
		"botasaurus",
		"langchain",
		"skyvern",
	}
	for _, ua := range scanners {
		if !detect.IsScannerUA(ua) {
			t.Fatalf("expected scanner ua: %q", ua)
		}
	}
	if detect.IsScannerUA("Mozilla/5.0 Chrome/120") {
		t.Fatal("unexpected scanner match for browser UA")
	}
}

func TestScoreProbe(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/.env", nil)
	r.Header.Set("User-Agent", "curl/8.0")
	res := detect.Score(r, testCfg())
	if res.Score < 40 {
		t.Fatalf("score=%d reasons=%v", res.Score, res.Reasons)
	}
}

func TestScoreHeaderConsistency(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36")
	r.Header.Set("Accept", "*/*")
	res := detect.ScoreDebug(r, testCfg())
	joined := strings.Join(res.Reasons, ",")
	if !strings.Contains(joined, "missing_accept_lang") &&
		!strings.Contains(joined, "missing_sec_fetch") &&
		!strings.Contains(joined, "star_accept_browser") {
		t.Fatalf("expected header signals score=%d reasons=%v", res.Score, res.Reasons)
	}
}

func TestScoreProxyBot(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Accept-Language", "en")
	r.Header.Set("Sec-Fetch-Site", "none")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	r.Header.Set("CF-Bot-Score", "10")
	res := detect.ScoreDebug(r, testCfg())
	if !strings.Contains(strings.Join(res.Reasons, ","), "proxy_bot_score") {
		t.Fatalf("expected proxy bot score reasons=%v", res.Reasons)
	}
}

func TestScoreFormSpam(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/forum/reply", strings.NewReader("body=hi"))
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := detect.ScoreDebug(r, testCfg())
	joined := strings.Join(res.Reasons, ",")
	if !strings.Contains(joined, "empty_form_context") {
		t.Fatalf("expected empty_form_context reasons=%v", res.Reasons)
	}
	if !strings.Contains(joined, "forum_write_path") {
		t.Fatalf("expected forum_write_path reasons=%v", res.Reasons)
	}
	if res.Score < 40 {
		t.Fatalf("spam post score=%d want >=40", res.Score)
	}

	ok := httptest.NewRequest(http.MethodPost, "/forum/reply", strings.NewReader("body=hi"))
	ok.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36")
	ok.Header.Set("Accept", "text/html")
	ok.Header.Set("Accept-Language", "en-US")
	ok.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ok.Header.Set("Origin", "https://forum.example")
	ok.Header.Set("Referer", "https://forum.example/topic/1")
	ok.Header.Set("Sec-Fetch-Site", "same-origin")
	ok.Header.Set("Sec-Fetch-Mode", "navigate")
	ok.Header.Set("Sec-Fetch-Dest", "document")
	clean := detect.ScoreDebug(ok, testCfg())
	joinedClean := strings.Join(clean.Reasons, ",")
	if strings.Contains(joinedClean, "empty_form_context") || strings.Contains(joinedClean, "forum_write_path") {
		t.Fatalf("legitimate form post should not spam-score reasons=%v", clean.Reasons)
	}
}

func TestScoreGeneralAPINoFalsePositive(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		ua     string
		ctype  string
		hdr    map[string]string
	}{
		{
			name:   "json api with browser ua and origin",
			method: http.MethodPost,
			path:   "/api/v1/orders",
			ua:     "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36",
			ctype:  "application/json",
			hdr: map[string]string{
				"Accept":          "application/json",
				"Accept-Language": "en-US",
				"Origin":          "https://app.example",
				"Sec-Fetch-Site":  "same-origin",
				"Sec-Fetch-Mode":  "cors",
				"Sec-Fetch-Dest":  "empty",
			},
		},
		{
			name:   "json api missing origin still not form spam",
			method: http.MethodPost,
			path:   "/api/v1/orders",
			ua:     "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36",
			ctype:  "application/json",
			hdr: map[string]string{
				"Accept":          "application/json",
				"Accept-Language": "en-US",
				"Sec-Fetch-Site":  "same-origin",
				"Sec-Fetch-Mode":  "cors",
				"Sec-Fetch-Dest":  "empty",
			},
		},
		{
			name:   "chat messages path is not forum spam",
			method: http.MethodPost,
			path:   "/api/messages",
			ua:     "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36",
			ctype:  "application/json",
			hdr: map[string]string{
				"Accept":          "application/json",
				"Accept-Language": "en-US",
				"Origin":          "https://app.example",
				"Sec-Fetch-Site":  "same-origin",
				"Sec-Fetch-Mode":  "cors",
				"Sec-Fetch-Dest":  "empty",
			},
		},
		{
			name:   "contacting segment does not match contact",
			method: http.MethodPost,
			path:   "/api/contacting",
			ua:     "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36",
			ctype:  "application/json",
			hdr: map[string]string{
				"Accept":          "application/json",
				"Accept-Language": "en-US",
				"Origin":          "https://app.example",
				"Sec-Fetch-Site":  "same-origin",
				"Sec-Fetch-Mode":  "cors",
				"Sec-Fetch-Dest":  "empty",
			},
		},
		{
			name:   "native mobile client",
			method: http.MethodPost,
			path:   "/api/v1/sync",
			ua:     "MyApp/3.2 (Android 14)",
			ctype:  "application/json",
			hdr: map[string]string{
				"Accept": "application/json",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"ok":true}`))
			r.Header.Set("User-Agent", tc.ua)
			if tc.ctype != "" {
				r.Header.Set("Content-Type", tc.ctype)
			}
			for k, v := range tc.hdr {
				r.Header.Set(k, v)
			}
			res := detect.ScoreDebug(r, testCfg())
			joined := strings.Join(res.Reasons, ",")
			if strings.Contains(joined, "empty_form_context") || strings.Contains(joined, "forum_write_path") {
				t.Fatalf("false positive reasons=%v score=%d", res.Reasons, res.Score)
			}
			if res.Score >= 40 {
				t.Fatalf("general traffic should stay under challenge score=%d reasons=%v", res.Score, res.Reasons)
			}
		})
	}
}

func TestForumWritePathSegments(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/blog/comments/new", strings.NewReader("x=1"))
	r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := detect.ScoreDebug(r, testCfg())
	if !strings.Contains(strings.Join(res.Reasons, ","), "forum_write_path") {
		t.Fatalf("segment comments should match reasons=%v", res.Reasons)
	}
}

func TestScoreAIUA(t *testing.T) {
	cases := []string{
		"Mozilla/5.0 AppleWebKit/537.36 (compatible; GPTBot/1.2)",
		"Mozilla/5.0 (compatible; Claude-SearchBot/1.0)",
		"Perplexity-User",
		"MistralAI-User/1.0",
		"Google-Agent",
	}
	for _, ua := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("User-Agent", ua)
		r.Header.Set("Accept", "text/html")
		res := detect.ScoreDebug(r, testCfg())
		if !strings.Contains(strings.Join(res.Reasons, ","), "ai_ua") {
			t.Fatalf("ua=%q reasons=%v", ua, res.Reasons)
		}
		if res.Score < testCfg().AIUAScore {
			t.Fatalf("ua=%q score=%d", ua, res.Score)
		}
	}
}

func TestForgeExpensiveHotScore(t *testing.T) {
	cfg := testCfg()
	cfg.ForgeExpensiveScore = 40
	r := httptest.NewRequest(http.MethodGet, "/owner/repo/compare/a...b", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Accept-Language", "en-US")
	r.Header.Set("Sec-Fetch-Site", "none")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	res := detect.ScoreDebug(r, cfg)
	if !strings.Contains(strings.Join(res.Reasons, ","), "forge_expensive") {
		t.Fatalf("reasons=%v", res.Reasons)
	}
	if res.Score < 40 {
		t.Fatalf("score=%d", res.Score)
	}
}

func TestForgeBrowseNoSingleHitScore(t *testing.T) {
	cfg := testCfg()
	cfg.ForgeExpensiveScore = 40
	r := httptest.NewRequest(http.MethodGet, "/owner/repo/src/branch/main", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Accept-Language", "en-US")
	r.Header.Set("Sec-Fetch-Site", "none")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	res := detect.ScoreDebug(r, cfg)
	if strings.Contains(strings.Join(res.Reasons, ","), "forge_expensive") {
		t.Fatalf("browse must not forge_expensive reasons=%v", res.Reasons)
	}
}

func FuzzIsScannerUA(f *testing.F) {
	f.Add("sqlmap")
	f.Add("Mozilla/5.0")
	f.Add("GPTBot")
	f.Add("Claude-SearchBot")
	f.Add("Perplexity-User")
	f.Add("playwright")
	f.Fuzz(func(t *testing.T, ua string) {
		_ = detect.IsScannerUA(ua)
		_ = detect.IsAIUA(ua)
	})
}
