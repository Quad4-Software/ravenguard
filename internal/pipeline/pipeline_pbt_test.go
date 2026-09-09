// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package pipeline_test

import (
	"fmt"
	"hash/fnv"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/access"
	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/challenge"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/detect"
	"github.com/Quad4-Software/ravenguard/internal/pipeline"
	"github.com/Quad4-Software/ravenguard/internal/router"
	"github.com/Quad4-Software/ravenguard/internal/ui"
)

// pbtRand returns a deterministic but per-test random source.
func pbtRand(t *testing.T) *rand.Rand {
	h := fnv.New64a()
	h.Write([]byte(t.Name()))
	return rand.New(rand.NewSource(int64(h.Sum64())))
}

// pbtConfig returns a reproducible challenge-always config for testing bypass.
func pbtConfig() config.Config {
	cfg := config.Default()
	cfg.Challenge.Secret = testSecret
	cfg.Challenge.Difficulty = 8
	cfg.Challenge.Mode = "always"
	cfg.Challenge.Algorithm = "sha256"
	cfg.Detect.Enabled = false
	cfg.RateLimit.Enabled = false
	cfg.Trust.Mode = "edge"
	cfg.Privacy.HashClientIP = false
	cfg.UI.StatusText = "x"
	cfg.UI.Brand = "y"
	return cfg
}

func pbtPages(t *testing.T, cfg config.Config) *ui.Pages {
	pages, err := ui.New(ui.SiteFromConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	return pages
}

func pbtChallengeManager(cfg config.Config) *challenge.Manager {
	return &challenge.Manager{
		Secret:     []byte(cfg.Challenge.Secret),
		Difficulty: cfg.Challenge.Difficulty,
		Algorithm:  cfg.Challenge.Algorithm,
		CookieName: cfg.Challenge.CookieName,
		CookieTTL:  cfg.Challenge.CookieTTL.Duration,
	}
}

func pbtUpstream() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func pbtHandler(t *testing.T, cfg config.Config) *pipeline.Handler {
	pages := pbtPages(t, cfg)
	chal := pbtChallengeManager(cfg)
	return pipeline.New(cfg, blocklist.New(), nil, nil, chal, pages, pbtUpstream(), nil, nil, nil, testPriv(cfg), nil, nil)
}

// pbtRouterHandler returns a handler using a real test origin as the only upstream.
// The returned origin server and router table are attached to the handler.
func pbtRouterHandler(t *testing.T, cfg config.Config, routes []router.Route) (*pipeline.Handler, *httptest.Server, *router.Table) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(origin.Close)

	pages := pbtPages(t, cfg)
	chal := pbtChallengeManager(cfg)
	h := pipeline.New(cfg, blocklist.New(), nil, nil, chal, pages, nil, nil, nil, nil, testPriv(cfg), nil, nil)

	rt := router.New(t.Context())
	upstreams := []router.Upstream{{ID: "u1", Name: "origin", URL: origin.URL, AllowHTTP1: true}}
	if err := rt.Replace(upstreams, routes); err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	h.SetRouter(rt)
	return h, origin, rt
}

// referenceSkipChallenge is an independent oracle for the expected bypass decision.
// It first checks config.Challenge.SkipPathPrefixes, then the configured route table.
func referenceSkipChallenge(r *http.Request, cfg config.Config, rt *router.Table) bool {
	for _, p := range cfg.Challenge.SkipPathPrefixes {
		if p != "" && strings.HasPrefix(r.URL.Path, p) {
			return true
		}
	}
	if rt == nil {
		return false
	}
	m, ok := rt.Lookup(r)
	return ok && m.Route.SkipChallenge
}

// responseIsBypass reports whether the pipeline let the request through to the origin.
func responseIsBypass(rr *httptest.ResponseRecorder) bool {
	return rr.Code == http.StatusOK && rr.Body.String() == "ok"
}

// randToken returns a random token using only characters that are safe against
// detect.AttackMatch so that PBT loops do not randomly trigger the attack path.
func randToken(r *rand.Rand, n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

func randString(r *rand.Rand, lo, hi int) string {
	if hi < lo {
		hi = lo
	}
	n := lo
	if hi > lo {
		n += r.Intn(hi - lo)
	}
	return randToken(r, n)
}

func randPath(r *rand.Rand, segs int) string {
	if segs <= 0 {
		return "/"
	}
	var b strings.Builder
	for range segs {
		b.WriteByte('/')
		b.WriteString(randString(r, 1, 10))
	}
	return b.String()
}

func randHost(r *rand.Rand, labels int) string {
	if labels <= 0 {
		return "example.com"
	}
	parts := make([]string, labels)
	for i := range parts {
		parts[i] = randString(r, 2, 8)
	}
	return strings.Join(parts, ".")
}

// requestFor builds a GET or WebSocket upgrade request for a given path and host.
func requestFor(t *testing.T, path, host string, ws bool) *http.Request {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	var req *http.Request
	if ws {
		req = wsUpgradeRequest(path, "192.0.2.1:1")
	} else {
		target := path
		if host != "" {
			target = "http://" + host + path
		}
		u, err := url.Parse(target)
		if err != nil {
			t.Fatalf("parse url: %v", err)
		}
		req = httptest.NewRequest(http.MethodGet, u.String(), nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "text/html")
	}
	req.Host = host
	req.RemoteAddr = "192.0.2.1:1"
	return req
}

func TestPBTSkipChallengePathPrefixes(t *testing.T) {
	cfg := pbtConfig()
	h := pbtHandler(t, cfg)
	r := pbtRand(t)

	prefixPool := []string{"/ws", "/api", "/api/v1", "/graphql", "/socket.io"}

	for i := range 200 {
		n := r.Intn(6)
		prefixes := make([]string, n)
		for j := range n {
			if r.Intn(3) == 0 {
				prefixes[j] = randPath(r, r.Intn(3)+1)
			} else {
				prefixes[j] = prefixPool[r.Intn(len(prefixPool))]
			}
		}
		cfg.Challenge.SkipPathPrefixes = prefixes
		h.ApplyConfig(cfg)

		var path string
		if n > 0 && r.Intn(2) == 0 {
			p := prefixes[r.Intn(n)]
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			p = strings.TrimSuffix(p, "/")
			path = p
			if r.Intn(2) == 0 {
				path = p + randPath(r, r.Intn(3))
			}
		} else {
			path = randPath(r, r.Intn(4)+1)
		}

		// Avoid triggering the attack signature path in this PBT.
		if detect.AttackMatch(&http.Request{URL: &url.URL{Path: path}}) != "" {
			continue
		}

		req := requestFor(t, path, randHost(r, r.Intn(3)+1), r.Intn(2) == 0)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		want := referenceSkipChallenge(req, cfg, nil)
		got := responseIsBypass(rr)
		if got != want {
			t.Fatalf("iter %d: path=%q prefixes=%v ws=%v want=%v got=%v code=%d body=%q",
				i, path, prefixes, req.Header.Get("Upgrade") == "websocket", want, got, rr.Code, rr.Body.String())
		}
	}
}

func TestPBTSkipChallengeRoutes(t *testing.T) {
	cfg := pbtConfig()
	r := pbtRand(t)

	hostPool := []string{"", "example.com", "api.example.com", "ws.example.com"}
	prefixPool := []string{"/", "/ws", "/api", "/api/v1", "/graphql", "/socket.io"}

	routes := []router.Route{
		{ID: "r0", Name: "root", Enabled: true, Hosts: []string{}, PathPrefix: "/", UpstreamID: "u1", SkipChallenge: false},
	}
	h, origin, rt := pbtRouterHandler(t, cfg, routes)

	for i := range 200 {
		n := r.Intn(5) + 1
		routes := make([]router.Route, n)
		for j := range n {
			host := hostPool[r.Intn(len(hostPool))]
			prefix := prefixPool[r.Intn(len(prefixPool))]
			skip := r.Intn(2) == 1
			routes[j] = router.Route{
				ID:            fmt.Sprintf("r%d", j),
				Name:          fmt.Sprintf("route%d", j),
				Enabled:       true,
				Hosts:         []string{},
				PathPrefix:    prefix,
				UpstreamID:    "u1",
				SkipChallenge: skip,
			}
			if host != "" {
				routes[j].Hosts = []string{host}
			}
		}

		if err := rt.Replace([]router.Upstream{{ID: "u1", URL: origin.URL, AllowHTTP1: true}}, routes); err != nil {
			t.Fatalf("iter %d: replace routes: %v", i, err)
		}

		var path string
		if r.Intn(2) == 0 {
			prefix := routes[r.Intn(n)].PathPrefix
			if prefix == "" {
				prefix = "/"
			}
			if !strings.HasPrefix(prefix, "/") {
				prefix = "/" + prefix
			}
			prefix = strings.TrimSuffix(prefix, "/")
			path = prefix
			if r.Intn(2) == 0 {
				path = prefix + randPath(r, r.Intn(3))
			}
		} else {
			path = randPath(r, r.Intn(4)+1)
		}

		if detect.AttackMatch(&http.Request{URL: &url.URL{Path: path}}) != "" {
			continue
		}

		host := "example.com"
		if r.Intn(2) == 0 {
			host = hostPool[r.Intn(len(hostPool))]
			if host == "" {
				host = "example.com"
			}
		}

		ws := r.Intn(2) == 0
		req := requestFor(t, path, host, ws)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		want := referenceSkipChallenge(req, cfg, rt)
		got := responseIsBypass(rr)
		if got != want {
			t.Fatalf("iter %d: path=%q host=%q ws=%v want=%v got=%v code=%d body=%q routes=%+v",
				i, path, host, ws, want, got, rr.Code, rr.Body.String(), routes)
		}
	}
}

func TestAdversarialPathPrefixEdgeCases(t *testing.T) {
	cfg := pbtConfig()
	h := pbtHandler(t, cfg)

	cases := []struct {
		prefix, path string
		want         bool
	}{
		{"/ws", "/ws", true},
		{"/ws", "/ws/", true},
		{"/ws", "/ws/chat", true},
		{"/ws", "/wschat", true},   // substring match due to strings.HasPrefix
		{"/ws", "/ws2", true},      // substring match due to strings.HasPrefix
		{"/ws/", "/wschat", false}, // trailing slash prevents matching the bare substring
		{"/ws/", "/ws2", false},
		{"", "/anything", false}, // empty prefix is ignored
		{"/", "/anything", true}, // root prefix matches everything
		{"/api", "/api/v1", true},
		{"/api", "/api", true},
		{"/api", "/apiv1", true},   // strings.HasPrefix matches the substring
		{"/api", "/api2", true},    // strings.HasPrefix matches the substring
		{"/api/", "/apiv1", false}, // trailing slash prevents matching the bare substring
		{"/api/", "/api2", false},
	}

	for _, c := range cases {
		cfg.Challenge.SkipPathPrefixes = []string{c.prefix}
		h.ApplyConfig(cfg)

		req := requestFor(t, c.path, "example.com", true)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		got := responseIsBypass(rr)
		if got != c.want {
			t.Fatalf("prefix=%q path=%q want=%v got=%v code=%d body=%q",
				c.prefix, c.path, c.want, got, rr.Code, rr.Body.String())
		}
	}
}

func TestAdversarialHostMatching(t *testing.T) {
	cfg := pbtConfig()
	routes := []router.Route{
		{ID: "r1", Name: "api", Enabled: true, Hosts: []string{"api.example.com"}, PathPrefix: "/api", UpstreamID: "u1", SkipChallenge: true},
		{ID: "r2", Name: "root", Enabled: true, Hosts: []string{}, PathPrefix: "/", UpstreamID: "u1", SkipChallenge: false},
	}
	h, _, rt := pbtRouterHandler(t, cfg, routes)

	cases := []struct {
		path, host string
		hdr        func(*http.Request)
		want       bool
	}{
		{"/api", "api.example.com", nil, true},
		{"/api", "api.example.com:8080", nil, true}, // port stripped
		{"/api", "API.EXAMPLE.COM", nil, true},      // case-insensitive
		{"/api", "other.example.com", nil, false},   // host mismatch, root route is not skipped
		{"/", "api.example.com", nil, false},        // prefix mismatch, root route not skipped
		{"/api", "other.example.com", func(r *http.Request) {
			r.Header.Set("X-Forwarded-Host", "api.example.com")
		}, false}, // X-Forwarded-Host must not spoof the route Host match
	}

	for _, c := range cases {
		req := requestFor(t, c.path, c.host, true)
		if c.hdr != nil {
			c.hdr(req)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		want := referenceSkipChallenge(req, cfg, rt)
		got := responseIsBypass(rr)
		if got != c.want || got != want {
			t.Fatalf("path=%q host=%q want=%v got=%v ref=%v code=%d body=%q",
				c.path, c.host, c.want, got, want, rr.Code, rr.Body.String())
		}
	}
}

func TestAdversarialHeaderForgery(t *testing.T) {
	cfg := pbtConfig()
	cfg.Challenge.SkipPathPrefixes = []string{"/_ws"}
	h := pbtHandler(t, cfg)

	cases := []struct {
		name string
		hdr  func(*http.Request)
		path string
		ws   bool
		want bool
	}{
		{"plain ws skipped", nil, "/_ws", true, true},
		{"x-forwarded-host", func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "attacker.com") }, "/_ws", true, true},
		{"x-forwarded-for", func(r *http.Request) { r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8") }, "/_ws", true, true},
		{"origin cross-site", func(r *http.Request) { r.Header.Set("Origin", "https://evil.com") }, "/_ws", true, true},
		{"fake hx-request", func(r *http.Request) { r.Header.Set("HX-Request", "true") }, "/_ws", true, true},
		// Missing Connection header makes it not a WebSocket, but the path is still skipped.
		{"missing connection", func(r *http.Request) { r.Header.Del("Connection") }, "/_ws", false, true},
		// Connection without Upgrade is not a WebSocket, but the path is still skipped.
		{"fake upgrade", func(r *http.Request) {
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Connection", "keep-alive")
		}, "/_ws", false, true},
		// Accept-json on a non-WS skipped path still proxies through.
		{"json accept", func(r *http.Request) { r.Header.Set("Accept", "application/json") }, "/_ws", false, true},
	}

	for _, c := range cases {
		req := requestFor(t, c.path, "example.com", c.ws)
		if c.hdr != nil {
			c.hdr(req)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		got := responseIsBypass(rr)
		if got != c.want {
			t.Fatalf("%s: want=%v got=%v code=%d body=%q", c.name, c.want, got, rr.Code, rr.Body.String())
		}
	}
}

func TestDifferentialSkipChallengeKnownInputs(t *testing.T) {
	cfg := pbtConfig()
	cfg.Challenge.SkipPathPrefixes = []string{"/_ws", "/_api"}
	h := pbtHandler(t, cfg)

	cases := []struct {
		path, host string
		ws         bool
		want       bool
	}{
		{"/_ws", "example.com", true, true},
		{"/_ws/chat", "example.com", true, true},
		{"/_api/v1/users", "example.com", true, true},
		{"/_api", "example.com", false, true},
		{"/_other", "example.com", true, false},
		{"/_ws", "api.example.com", false, true},
	}

	for _, c := range cases {
		req := requestFor(t, c.path, c.host, c.ws)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		want := referenceSkipChallenge(req, cfg, nil)
		got := responseIsBypass(rr)
		if got != c.want || got != want {
			t.Fatalf("path=%q host=%q ws=%v want=%v got=%v ref=%v code=%d body=%q",
				c.path, c.host, c.ws, c.want, got, want, rr.Code, rr.Body.String())
		}
	}
}

func TestDifferentialSkipChallengeRouteInputs(t *testing.T) {
	cfg := pbtConfig()
	routes := []router.Route{
		{ID: "r1", Name: "ws", Enabled: true, Hosts: []string{}, PathPrefix: "/ws", UpstreamID: "u1", SkipChallenge: true},
		{ID: "r2", Name: "api", Enabled: true, Hosts: []string{"api.example.com"}, PathPrefix: "/api", UpstreamID: "u1", SkipChallenge: false},
		{ID: "r3", Name: "root", Enabled: true, Hosts: []string{}, PathPrefix: "/", UpstreamID: "u1", SkipChallenge: false},
	}
	h, _, rt := pbtRouterHandler(t, cfg, routes)

	cases := []struct {
		path, host string
		ws         bool
		want       bool
	}{
		{"/ws", "example.com", true, true},       // r1 matches, skip
		{"/ws/chat", "example.com", true, true},  // r1 matches, skip
		{"/ws", "api.example.com", true, true},   // r1 matches first (r2 host ok but prefix mismatch)
		{"/api", "api.example.com", true, false}, // r2 matches, no skip
		{"/api", "example.com", true, false},     // r2 host mismatch, r3 prefix / matches, no skip
		{"/", "example.com", false, false},       // r3, no skip
		{"/anything", "other.com", false, false}, // r3, no skip
	}

	for _, c := range cases {
		req := requestFor(t, c.path, c.host, c.ws)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		want := referenceSkipChallenge(req, cfg, rt)
		got := responseIsBypass(rr)
		if got != c.want || got != want {
			t.Fatalf("path=%q host=%q ws=%v want=%v got=%v ref=%v code=%d body=%q",
				c.path, c.host, c.ws, c.want, got, want, rr.Code, rr.Body.String())
		}
	}
}

// referenceAccessChallenge is a simple reference for the combined
// challenge and access-policy decision on a protected route.
func referenceAccessChallenge(skip, hasClearance, hasHeader bool) bool {
	if skip {
		return hasHeader
	}
	return hasClearance && hasHeader
}

func TestDifferentialAccessPolicyChallengeDecision(t *testing.T) {
	cfg := pbtConfig()
	routes := []router.Route{
		{ID: "r1", Name: "protected", Enabled: true, Hosts: []string{}, PathPrefix: "/protected", UpstreamID: "u1", SkipChallenge: false},
	}
	h, origin, rt := pbtRouterHandler(t, cfg, routes)

	am := access.NewManager([]byte(testSecret))
	am.Replace([]access.Policy{
		{
			ID:   "p1",
			Name: "token",
			Mode: access.ModeAll,
			Rules: []access.Rule{
				{Type: access.RuleHeader, HeaderName: "X-Token", HeaderValue: "secret"},
			},
		},
	})
	h.SetAccess(am)

	cases := []struct {
		skip, hasClearance, hasHeader bool
		want                          bool
	}{
		{false, false, false, false},
		{false, false, true, false},
		{false, true, false, false},
		{false, true, true, true},
		{true, false, false, false},
		{true, false, true, true},
		{true, true, false, false},
		{true, true, true, true},
	}

	for i, c := range cases {
		rt.Replace([]router.Upstream{{ID: "u1", URL: origin.URL, AllowHTTP1: true}}, []router.Route{
			{ID: "r1", Name: "protected", Enabled: true, Hosts: []string{}, PathPrefix: "/protected", UpstreamID: "u1", AccessPolicyID: "p1", SkipChallenge: c.skip},
		})

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "text/html")
		req.Host = "example.com"
		req.RemoteAddr = "192.0.2.1:1"

		if c.hasHeader {
			req.Header.Set("X-Token", "secret")
		}
		if c.hasClearance {
			cookie := pbtChallengeManager(cfg).ClearanceCookie("192.0.2.1", "ray", false)
			req.AddCookie(cookie)
		}

		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		want := referenceAccessChallenge(c.skip, c.hasClearance, c.hasHeader)
		got := responseIsBypass(rr)
		if got != want {
			t.Fatalf("case %d skip=%v clear=%v header=%v want=%v got=%v code=%d body=%q",
				i, c.skip, c.hasClearance, c.hasHeader, want, got, rr.Code, rr.Body.String())
		}
	}
}

func TestMetamorphicSkipChallengeInvariants(t *testing.T) {
	t.Run("skipprefix_allows_always", func(t *testing.T) {
		cfg := pbtConfig()
		cfg.Challenge.SkipPathPrefixes = []string{"/_ws"}
		h := pbtHandler(t, cfg)

		for i := range 100 {
			req := requestFor(t, "/_ws/random", fmt.Sprintf("h%d.example.com", i), i%2 == 0)
			req.Header.Set("Accept", "application/json")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if !responseIsBypass(rr) {
				t.Fatalf("iter %d: skipprefix must always allow, got code=%d body=%q", i, rr.Code, rr.Body.String())
			}
		}
	})

	t.Run("toggle_route_skip_challenge", func(t *testing.T) {
		cfg := pbtConfig()
		routes := []router.Route{
			{ID: "r1", Name: "ws", Enabled: true, Hosts: []string{}, PathPrefix: "/ws", UpstreamID: "u1", SkipChallenge: true},
		}
		h, origin, rt := pbtRouterHandler(t, cfg, routes)

		req1 := requestFor(t, "/ws", "example.com", true)
		rr1 := httptest.NewRecorder()
		h.ServeHTTP(rr1, req1)
		if !responseIsBypass(rr1) {
			t.Fatalf("skip=true should bypass")
		}

		// Toggle the same route to require challenge.
		routes[0].SkipChallenge = false
		if err := rt.Replace([]router.Upstream{{ID: "u1", URL: origin.URL, AllowHTTP1: true}}, routes); err != nil {
			t.Fatal(err)
		}

		req2 := requestFor(t, "/ws", "example.com", true)
		rr2 := httptest.NewRecorder()
		h.ServeHTTP(rr2, req2)
		if responseIsBypass(rr2) {
			t.Fatalf("skip=false should not bypass")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		cfg := pbtConfig()
		routes := []router.Route{
			{ID: "r1", Name: "ws", Enabled: true, Hosts: []string{}, PathPrefix: "/ws", UpstreamID: "u1", SkipChallenge: true},
		}
		h, _, _ := pbtRouterHandler(t, cfg, routes)

		var firstBypass bool
		var firstCode int
		for i := range 20 {
			req := requestFor(t, "/ws", "example.com", true)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if i == 0 {
				firstBypass = responseIsBypass(rr)
				firstCode = rr.Code
			}
			if responseIsBypass(rr) != firstBypass || rr.Code != firstCode {
				t.Fatalf("non-deterministic: iter %d code=%d bypass=%v first=%d/%v",
					i, rr.Code, responseIsBypass(rr), firstCode, firstBypass)
			}
		}
	})
}
