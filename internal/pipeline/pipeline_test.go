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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/allowlist"
	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/challenge"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/detect"
	"github.com/Quad4-Software/ravenguard/internal/iputil"
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
	return pipeline.New(cfg, lists, nil, nil, chal, pages, upstream, trusted, nil, nil, testPriv(cfg), nil, nil)
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

func solvedPayload(t *testing.T, m *challenge.Manager, bindID string, gate string, env challenge.EnvAttestation) string {
	t.Helper()
	m.Algorithm = "sha256"
	if gate == "" {
		gate = challenge.GateInteractive
	}
	ch, err := m.IssueChallenge(bindID, challenge.RiskLow, gate)
	if err != nil {
		t.Fatal(err)
	}
	sol, err := challenge.SolveChallenge(ch)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := challenge.EncodePayload(challenge.Payload{
		V: ch.V, Algorithm: ch.Algorithm, Challenge: ch.Challenge, Salt: ch.Salt,
		Difficulty: ch.Difficulty, MaxNumber: ch.MaxNumber, Expires: ch.Expires,
		Bind: ch.Bind, Gate: ch.Gate, Params: ch.Params, Signature: ch.Signature,
		Solution: strconv.FormatUint(sol, 10),
		Env:      env,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
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
	if !strings.Contains(body, "rg-check") {
		t.Fatalf("missing challenge page: %s", body[:min(200, len(body))])
	}
	// Probe + scanner UA lands in high risk so the gate is interactive.
	if !strings.Contains(body, `auto="off"`) {
		t.Fatalf("expected interactive gate for high risk: %s", body[:min(400, len(body))])
	}

	priv := privacy.New(privacy.Config{
		HashClientIP: true,
		Secret:       []byte(testSecret),
		LogIP:        "hash",
	})
	bindID := priv.ClientKey("192.0.2.30")
	m := &challenge.Manager{Secret: []byte(testSecret), Difficulty: 8, CookieName: "rg_clear", CookieTTL: time.Hour, Algorithm: "sha256"}
	raw := solvedPayload(t, m, bindID, challenge.GateInteractive, challenge.EnvAttestation{Interacted: true, SolveMs: 200})
	payloadJSON, _ := json.Marshal(map[string]any{"payload": raw, "ray": "test"})
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
	m := &challenge.Manager{Secret: []byte(testSecret), Difficulty: 8, CookieName: "rg_clear", CookieTTL: time.Hour, Algorithm: "sha256"}
	raw := solvedPayload(t, m, bindID, challenge.GateInvisible, challenge.EnvAttestation{Webdriver: true, Interacted: true, SolveMs: 200, NoPlugins: true})
	payloadJSON, _ := json.Marshal(map[string]any{"payload": raw})
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

func TestInvisibleGateAlwaysMode(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "always"
		cfg.Detect.Enabled = false
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.RemoteAddr = "192.0.2.31:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `auto="onload"`) || !strings.Contains(body, `display="invisible"`) {
		t.Fatalf("expected invisible gate: %s", body[:min(400, len(body))])
	}
}

func TestAttackModeInteractiveGate(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "attack"
		cfg.Detect.Enabled = false
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.RemoteAddr = "192.0.2.40:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `auto="off"`) {
		t.Fatalf("expected interactive auto=off: %s", body[:min(400, len(body))])
	}
	if strings.Contains(body, `display="invisible"`) {
		t.Fatal("attack mode must not use invisible display")
	}
}

func TestHTMXChallengeRedirectsNotHTML(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "always"
		cfg.Detect.Enabled = false
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/system_status", nil)
	req.Host = "git.example"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("HX-Request", "true")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Referer", "https://git.example/admin")
	req.RemoteAddr = "192.0.2.41:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("HX-Redirect") != "/admin" {
		t.Fatalf("HX-Redirect=%q body=%q", rr.Header().Get("HX-Redirect"), rr.Body.String())
	}
	if rr.Header().Get("X-RavenGuard-Challenge") != "required" {
		t.Fatal("missing challenge header")
	}
	if strings.Contains(rr.Body.String(), "rg-check") {
		t.Fatal("HTMX challenge must not return interstitial HTML")
	}
}

func TestJSONChallengeRequiredBody(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "always"
		cfg.Detect.Enabled = false
	})
	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.RemoteAddr = "192.0.2.42:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("content-type=%q", rr.Header().Get("Content-Type"))
	}
	body := rr.Body.String()
	if !strings.Contains(body, "challenge_required") {
		t.Fatalf("body=%q", body)
	}
	if !strings.Contains(body, `"data":[]`) && !strings.Contains(body, `"data": []`) {
		t.Fatalf("expected forge-safe data array: %q", body)
	}
}

func TestDetectModeAllowsSameOriginFetchWithoutClearance(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "detect"
		cfg.Challenge.Enabled = true
		cfg.Detect.Enabled = true
		cfg.Detect.ChallengeScore = 1
		cfg.Detect.MissingUAScore = 50
		cfg.Detect.BlockScore = 90
	})
	req := httptest.NewRequest(http.MethodGet, "/repo/search?uid=1&team_id=undefined&q=", nil)
	req.Host = "git.example"
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Referer", "https://git.example/")
	req.RemoteAddr = "192.0.2.77:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("detect-mode same-origin fetch should proxy, code=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "ok" {
		t.Fatalf("body=%q", rr.Body.String())
	}
	if rr.Header().Get("X-RavenGuard-Challenge") != "" {
		t.Fatal("must not challenge same-origin SPA fetch in detect mode")
	}
}

func TestAlwaysModeStillChallengesSameOriginFetch(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "always"
		cfg.Detect.Enabled = false
	})
	req := httptest.NewRequest(http.MethodGet, "/repo/search?uid=1", nil)
	req.Host = "git.example"
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Referer", "https://git.example/")
	req.RemoteAddr = "192.0.2.78:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("always mode must still gate fetch, code=%d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "challenge_required") {
		t.Fatalf("body=%q", rr.Body.String())
	}
}

func TestDetectModeAllowsForgeEventSource(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "detect"
		cfg.Challenge.Enabled = true
		cfg.Detect.Enabled = true
		cfg.Detect.ChallengeScore = 1
		cfg.Detect.MissingUAScore = 50
		cfg.Detect.BlockScore = 90
	})
	req := httptest.NewRequest(http.MethodGet, "/user/events", nil)
	req.Host = "git.example"
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Referer", "https://git.example/")
	req.RemoteAddr = "192.0.2.79:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Forge EventSource must not be JSON-gated in detect mode, code=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestDetectModeAllowsSharedWorkerScript(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "detect"
		cfg.Challenge.Enabled = true
		cfg.Detect.Enabled = true
		cfg.Detect.ChallengeScore = 1
		cfg.Detect.MissingUAScore = 50
		cfg.Detect.BlockScore = 90
	})
	req := httptest.NewRequest(http.MethodGet, "/assets/js/eventsource.sharedworker.js", nil)
	req.Host = "git.example"
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Fetch-Dest", "sharedworker")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Referer", "https://git.example/")
	req.RemoteAddr = "192.0.2.80:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("sharedworker script must proxy in detect mode, code=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "challenge_required") || strings.Contains(rr.Body.String(), "rg-check") {
		t.Fatal("must not return challenge payload for sharedworker script")
	}
}

func TestDocumentChallengeEmbedsNext(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "always"
		cfg.Detect.Enabled = false
	})
	req := httptest.NewRequest(http.MethodGet, "/repos/foo", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.RemoteAddr = "192.0.2.43:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `next: "/repos/foo"`) && !strings.Contains(body, `next:"/repos/foo"`) {
		t.Fatalf("expected next in bootstrap: %s", body[strings.Index(body, "window"):min(len(body), strings.Index(body, "window")+280)])
	}
}

func TestEnvProbeOffSkipsAutomation(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "always"
		cfg.Challenge.EnvProbe = "off"
		cfg.Detect.Enabled = false
		cfg.Privacy.HashClientIP = false
	})
	bindID := "192.0.2.91"
	m := &challenge.Manager{Secret: []byte(testSecret), Difficulty: 8, CookieName: "rg_clear", CookieTTL: time.Hour, Algorithm: "sha256"}
	raw := solvedPayload(t, m, bindID, challenge.GateInvisible, challenge.EnvAttestation{Webdriver: true, Interacted: false, SolveMs: 200})
	payloadJSON, _ := json.Marshal(map[string]any{"payload": raw})
	creq := httptest.NewRequest(http.MethodPost, "/_rg/challenge", bytes.NewReader(payloadJSON))
	creq.Header.Set("Content-Type", "application/json")
	creq.RemoteAddr = "192.0.2.91:1"
	crr := httptest.NewRecorder()
	h.ServeHTTP(crr, creq)
	if crr.Code != http.StatusOK {
		t.Fatalf("env_probe=off should allow automation post=%d %s", crr.Code, crr.Body.String())
	}
}

func TestEscalateAfterFailedVerify(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "always"
		cfg.Detect.Enabled = false
		cfg.Privacy.HashClientIP = false
	})
	creq := httptest.NewRequest(http.MethodPost, "/_rg/challenge", bytes.NewReader([]byte(`{"payload":"bad"}`)))
	creq.Header.Set("Content-Type", "application/json")
	creq.RemoteAddr = "192.0.2.32:1"
	crr := httptest.NewRecorder()
	h.ServeHTTP(crr, creq)
	if crr.Code == http.StatusOK {
		t.Fatal("expected failed verify")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.RemoteAddr = "192.0.2.32:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, `auto="off"`) {
		t.Fatalf("expected interactive after fail: %s", body[:min(400, len(body))])
	}
}

func TestChallengeSecureFromProto(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "always"
		cfg.Detect.Enabled = false
		cfg.Privacy.HashClientIP = false
		cfg.Trust.Mode = "behind_proxy"
		cfg.Trust.TrustedProxies = []string{"192.0.2.0/24"}
		cfg.Trust.ProtoHeader = "X-Forwarded-Proto"
	})
	priv := privacy.New(privacy.Config{HashClientIP: false, Secret: []byte(testSecret), LogIP: "off"})
	bindID := priv.ClientKey("192.0.2.77")
	m := &challenge.Manager{Secret: []byte(testSecret), Difficulty: 8, CookieName: "rg_clear", CookieTTL: time.Hour, Algorithm: "sha256"}
	raw := solvedPayload(t, m, bindID, challenge.GateInvisible, challenge.EnvAttestation{Interacted: true, SolveMs: 200})
	payloadJSON, _ := json.Marshal(map[string]any{"payload": raw})
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
	if !strings.Contains(rr.Body.String(), "rg-check") {
		t.Fatal("expected challenge page")
	}
}

func TestAllowlistSkipsChallenge(t *testing.T) {
	dir := t.TempDir()
	ipFile := filepath.Join(dir, "ips.txt")
	uaFile := filepath.Join(dir, "ua.txt")
	hdrFile := filepath.Join(dir, "headers.txt")
	_ = os.WriteFile(ipFile, []byte("192.0.2.80\n"), 0o600)
	_ = os.WriteFile(uaFile, []byte("HealthCheckBot\n"), 0o600)
	_ = os.WriteFile(hdrFile, []byte("X-RG-Allow: trusted\n"), 0o600)

	allows := allowlist.New()
	if err := allows.Load([]string{ipFile}, []string{uaFile}, []string{hdrFile}); err != nil {
		t.Fatal(err)
	}

	newH := func() *pipeline.Handler {
		cfg := config.Default()
		cfg.Challenge.Secret = testSecret
		cfg.Challenge.Mode = "always"
		cfg.Challenge.Enabled = true
		cfg.Detect.Enabled = true
		cfg.RateLimit.Enabled = false
		cfg.Privacy.HashClientIP = false
		pages, err := ui.New(ui.Site{Brand: "RavenGuard", StatusText: "x", Prefix: "/_rg"})
		if err != nil {
			t.Fatal(err)
		}
		chal := &challenge.Manager{
			Secret:     []byte(cfg.Challenge.Secret),
			Difficulty: 8,
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
		return h
	}

	cases := []struct {
		name string
		mut  func(*http.Request)
	}{
		{"ip", func(r *http.Request) { r.RemoteAddr = "192.0.2.80:1" }},
		{"ua", func(r *http.Request) {
			r.RemoteAddr = "192.0.2.81:1"
			r.Header.Set("User-Agent", "HealthCheckBot/1.0")
		}},
		{"header", func(r *http.Request) {
			r.RemoteAddr = "192.0.2.82:1"
			r.Header.Set("X-RG-Allow", "trusted")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Header.Set("Accept", "text/html")
			tc.mut(req)
			rr := httptest.NewRecorder()
			newH().ServeHTTP(rr, req)
			if rr.Code != http.StatusOK || rr.Body.String() != "ok" {
				t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.RemoteAddr = "192.0.2.83:1"
	rr := httptest.NewRecorder()
	newH().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("unlisted code=%d", rr.Code)
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
		Algorithm:  "sha256",
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
		{"/_rg/test/challenge", 403, "__g__"},
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

func TestEdgeModeIgnoresForwardedIP(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Trust.Mode = "edge"
		cfg.Trust.TrustedProxies = []string{"10.0.0.0/8"}
		cfg.Trust.RealIPHeader = "X-Real-IP"
		cfg.Challenge.Enabled = false
		cfg.Detect.Enabled = false
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Real-IP", "203.0.113.9")
	req.RemoteAddr = "10.0.0.5:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d", rr.Code)
	}
}

func TestHealthzBypassesGuard(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "always"
		cfg.Detect.Enabled = true
		cfg.Challenge.Enabled = true
	})
	for _, path := range []string{"/healthz", "/_rg/healthz"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "192.0.2.50:1"
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s code=%d body=%q", path, rr.Code, rr.Body.String())
		}
		if rr.Body.String() != "ok\n" {
			t.Fatalf("%s body=%q", path, rr.Body.String())
		}
	}
}

func TestStealthOmitsRayHeaderAndBrandFingerprints(t *testing.T) {
	h := testHandler(t, func(cfg *config.Config) {
		cfg.Challenge.Mode = "always"
		cfg.Detect.Enabled = false
		cfg.Stealth.RayHeader = ""
		cfg.Stealth.GenericCopy = true
		cfg.Stealth.HideBrandMark = true
		cfg.Stealth.ElementName = "rg-check"
		cfg.Stealth.BootstrapGlobal = "__g__"
		cfg.Challenge.PathPrefix = "/gate"
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.RemoteAddr = "192.0.2.91:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rr.Code)
	}
	if rr.Header().Get("X-RavenGuard-Ray") != "" {
		t.Fatal("expected no X-RavenGuard-Ray header")
	}
	body := rr.Body.String()
	if strings.Contains(body, "ravenguard-widget") {
		t.Fatal("unexpected ravenguard-widget fingerprint")
	}
	if strings.Contains(body, "window.__RG__") {
		t.Fatal("unexpected __RG__ fingerprint")
	}
	if !strings.Contains(body, "rg-check") && !strings.Contains(body, "__g__") {
		t.Fatalf("expected stealth widget bootstrap in body=%s", body[:min(200, len(body))])
	}
}

func TestCaptchaStubGate(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = testSecret
	cfg.Challenge.Difficulty = 8
	cfg.Challenge.Mode = "attack"
	cfg.Challenge.EnvProbe = "off"
	cfg.Challenge.Captcha.Enabled = true
	cfg.Challenge.Captcha.Provider = "stub"
	cfg.Challenge.Captcha.Token = "ok"
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
		CookieTTL:  time.Hour,
		Captcha:    challenge.StubCaptcha{Token: "ok"},
	}
	lists := blocklist.New()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	h := pipeline.New(cfg, lists, nil, nil, chal, pages, upstream, nil, nil, nil, testPriv(cfg), nil, nil)

	bindID := "192.0.2.55"
	raw := solvedPayload(t, chal, bindID, challenge.GateInteractive, challenge.EnvAttestation{Interacted: true, SolveMs: 200})
	bad, _ := json.Marshal(map[string]any{"payload": raw, "captcha": "nope"})
	creq := httptest.NewRequest(http.MethodPost, "/_rg/challenge", bytes.NewReader(bad))
	creq.Header.Set("Content-Type", "application/json")
	creq.RemoteAddr = "192.0.2.55:1"
	crr := httptest.NewRecorder()
	h.ServeHTTP(crr, creq)
	if crr.Code == http.StatusOK {
		t.Fatal("expected captcha refuse")
	}

	raw2 := solvedPayload(t, chal, bindID, challenge.GateInteractive, challenge.EnvAttestation{Interacted: true, SolveMs: 200})
	good, _ := json.Marshal(map[string]any{"payload": raw2, "captcha": "ok"})
	creq2 := httptest.NewRequest(http.MethodPost, "/_rg/challenge", bytes.NewReader(good))
	creq2.Header.Set("Content-Type", "application/json")
	creq2.RemoteAddr = "192.0.2.55:1"
	crr2 := httptest.NewRecorder()
	h.ServeHTTP(crr2, creq2)
	if crr2.Code != http.StatusOK {
		t.Fatalf("expected captcha ok post=%d %s", crr2.Code, crr2.Body.String())
	}
}
