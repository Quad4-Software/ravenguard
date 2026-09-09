// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package router_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/router"
)

// candidate is a compiled route used by the independent oracle.
type candidate struct {
	idx      int
	route    router.Route
	upstream router.Upstream
	prefix   string
	hosts    map[string]struct{}
}

// matchPrefixOracle mirrors the unexported matchPrefix helper.
func matchPrefixOracle(path, prefix string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	if path == prefix {
		return true
	}
	trimmed := strings.TrimSuffix(prefix, "/")
	return path == trimmed || strings.HasPrefix(path, trimmed+"/")
}

// stripPortOracle mirrors the unexported stripPort helper.
func stripPortOracle(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return host
	}
	if host[0] == '[' {
		if end := strings.IndexByte(host, ']'); end > 0 {
			return host[1:end]
		}
		return host
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		if strings.Count(host, ":") == 1 {
			return host[:i]
		}
	}
	return host
}

// normalizeHostOracle mirrors host normalization in Table.Replace.
func normalizeHostOracle(host string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return "", false
	}
	return h, true
}

// referenceBest is an independent oracle for Table.Lookup.
// It returns every route that is tied for the best match according to the
// documented precedence: highest priority, then longest prefix, then any host
// list constraint.  The router may break ties arbitrarily, so the caller checks
// that the matched route belongs to the returned set.
func referenceBest(upstreams []router.Upstream, routes []router.Route, reqHost, reqPath string) ([]candidate, bool) {
	upByID := make(map[string]router.Upstream, len(upstreams))
	for _, u := range upstreams {
		upByID[u.ID] = u
	}

	var cands []candidate
	for i, rt := range routes {
		if !rt.Enabled {
			continue
		}
		up, ok := upByID[rt.UpstreamID]
		if !ok {
			continue
		}
		prefix := rt.PathPrefix
		if prefix == "" {
			prefix = "/"
		}
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		hosts := make(map[string]struct{})
		for _, h := range rt.Hosts {
			h, ok := normalizeHostOracle(h)
			if !ok {
				continue
			}
			hosts[h] = struct{}{}
		}
		cands = append(cands, candidate{
			idx:      i,
			route:    rt,
			upstream: up,
			prefix:   prefix,
			hosts:    hosts,
		})
	}

	host := stripPortOracle(reqHost)
	if reqPath == "" {
		reqPath = "/"
	}

	var best []candidate
	var bestPrio int
	var bestLen int
	found := false
	for _, c := range cands {
		if len(c.hosts) > 0 {
			if _, ok := c.hosts[host]; !ok {
				continue
			}
		}
		if !matchPrefixOracle(reqPath, c.prefix) {
			continue
		}
		candPrio := c.route.Priority
		candLen := len(c.prefix)
		if !found ||
			candPrio > bestPrio ||
			(candPrio == bestPrio && candLen > bestLen) {
			best = []candidate{c}
			bestPrio = candPrio
			bestLen = candLen
			found = true
		} else if candPrio == bestPrio && candLen == bestLen {
			best = append(best, c)
		}
	}
	return best, found
}

// matchInCandidates checks that got is one of the best candidates.
func matchInCandidates(got router.Match, cands []candidate) bool {
	for _, c := range cands {
		if got.Route.ID == c.route.ID &&
			got.Upstream.ID == c.upstream.ID &&
			got.Route.Priority == c.route.Priority &&
			got.Route.SkipChallenge == c.route.SkipChallenge {
			return true
		}
	}
	return false
}

func genString(r *rand.Rand, chars string, maxLen int) string {
	n := r.IntN(maxLen + 1)
	if n == 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[r.IntN(len(chars))]
	}
	return string(b)
}

var pathChars = "abcdefghijklmnopqrstuvwxyz0123456789-"

func genPathPrefix(r *rand.Rand) string {
	switch r.IntN(10) {
	case 0:
		return ""
	case 1, 2:
		return "/"
	}
	n := r.IntN(4) + 1
	parts := make([]string, n)
	for i := range parts {
		parts[i] = genString(r, pathChars, r.IntN(8)+1)
	}
	p := "/" + strings.Join(parts, "/")
	if r.IntN(2) == 0 {
		p += "/"
	}
	return p
}

var hostChars = "abcdefghijklmnopqrstuvwxyz0123456789-"

var hostCorpus = []string{
	"",
	"example.com",
	"api.example.com",
	"localhost",
	"127.0.0.1",
	"::1",
	"EXAMPLE.COM",
	"Example.COM:8080",
	" example.com ",
	"[::1]:1234",
	"other.test",
}

func genHost(r *rand.Rand, fromCorpus bool) string {
	if fromCorpus && r.IntN(4) > 0 {
		return hostCorpus[r.IntN(len(hostCorpus))]
	}
	return "host-" + genString(r, hostChars, r.IntN(6)+1) + ".test"
}

func genRequestPath(r *rand.Rand, prefixes []string) string {
	if len(prefixes) > 0 && r.IntN(3) > 0 {
		p := prefixes[r.IntN(len(prefixes))]
		switch r.IntN(8) {
		case 0:
			return p
		case 1:
			if p != "/" {
				return p + "/"
			}
		case 2:
			if p != "/" {
				return p + "/sub"
			}
		case 3:
			if p != "/" {
				return strings.TrimSuffix(p, "/")
			}
		case 4:
			if p != "/" {
				return p + "extra"
			}
		case 5:
			if p != "/" && len(p) > 1 {
				return p[:len(p)-1]
			}
		case 6:
			// percent-encode a random suffix segment
			if p != "/" {
				return p + "/%61x"
			}
		}
	}
	n := r.IntN(4) + 1
	parts := make([]string, n)
	for i := range parts {
		parts[i] = genString(r, pathChars, r.IntN(6)+1)
	}
	return "/" + strings.Join(parts, "/")
}

func makeRequest(host, path string) *http.Request {
	// Use a fixed base URL and set the path directly so arbitrary strings do not
	// trigger url.Parse failures during random generation.
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = host
	req.URL.Path = path
	return req
}

func randomTable(ctx context.Context, t *testing.T, r *rand.Rand, numUpstreams, numRoutes int) (*router.Table, []router.Upstream, []router.Route, error) {
	t.Helper()

	upstreams := make([]router.Upstream, numUpstreams)
	for i := range upstreams {
		port := 10000 + r.IntN(55535)
		upstreams[i] = router.Upstream{
			ID:           fmt.Sprintf("u-%d", i),
			Name:         fmt.Sprintf("upstream-%d", i),
			URL:          fmt.Sprintf("http://127.0.0.1:%d", port),
			MaxIdleConns: 1,
		}
	}

	routes := make([]router.Route, numRoutes)
	for i := range routes {
		upID := upstreams[r.IntN(len(upstreams))].ID
		numHosts := r.IntN(4)
		hosts := make([]string, numHosts)
		for j := range hosts {
			hosts[j] = genHost(r, true)
		}
		routes[i] = router.Route{
			ID:            fmt.Sprintf("r-%d", i),
			Name:          fmt.Sprintf("route-%d", i),
			Enabled:       r.IntN(10) > 0,
			Hosts:         hosts,
			PathPrefix:    genPathPrefix(r),
			UpstreamID:    upID,
			StripPrefix:   r.IntN(2) == 0,
			Priority:      r.IntN(50) - 10,
			SkipChallenge: r.IntN(2) == 0,
		}
	}

	tab := router.New(ctx)
	if err := tab.Replace(upstreams, routes); err != nil {
		tab.Close()
		return nil, nil, nil, err
	}
	return tab, upstreams, routes, nil
}

func randomRequest(r *rand.Rand, routes []router.Route) *http.Request {
	host := genHost(r, true)
	var prefixes []string
	for _, rt := range routes {
		p := rt.PathPrefix
		if p == "" {
			p = "/"
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		prefixes = append(prefixes, p)
	}
	path := genRequestPath(r, prefixes)
	return makeRequest(host, path)
}

// cloneUpstreams returns a deep copy of the upstream slice.
func cloneUpstreams(upstreams []router.Upstream) []router.Upstream {
	out := make([]router.Upstream, len(upstreams))
	for i, u := range upstreams {
		out[i] = u
		if u.SetHeaders != nil {
			out[i].SetHeaders = append([]string(nil), u.SetHeaders...)
		}
		if u.HealthSuccessCodes != nil {
			out[i].HealthSuccessCodes = append([]int(nil), u.HealthSuccessCodes...)
		}
	}
	return out
}

func routesWithIDDisabled(routes []router.Route, id string) []router.Route {
	out := make([]router.Route, len(routes))
	copy(out, routes)
	for i := range out {
		if out[i].ID == id {
			out[i].Enabled = false
		}
	}
	return out
}

func TestRouteMatchingPBT(t *testing.T) {
	r := rand.New(rand.NewPCG(11, 22))
	const (
		tables       = 80
		reqsPerTable = 30
	)

	for range tables {
		func() {
			ctx := context.Background()
			tab, upstreams, routes, err := randomTable(ctx, t, r, r.IntN(4)+1, r.IntN(7)+1)
			if err != nil {
				t.Fatalf("replace: %v", err)
			}
			defer tab.Close()

			for range reqsPerTable {
				req := randomRequest(r, routes)
				got, ok := tab.Lookup(req)
				best, wantOK := referenceBest(upstreams, routes, req.Host, req.URL.Path)
				if ok != wantOK {
					t.Fatalf("lookup ok=%v want %v for host=%q path=%q", ok, wantOK, req.Host, req.URL.Path)
				}
				if ok && !matchInCandidates(got, best) {
					t.Fatalf("lookup route %s/%s not in best set for host=%q path=%q", got.Route.ID, got.Upstream.ID, req.Host, req.URL.Path)
				}

				got2, ok2 := tab.Lookup(req)
				if ok != ok2 {
					t.Fatalf("lookup ok not deterministic: first %v second %v", ok, ok2)
				}
				if ok2 {
					if got2.Route.ID != got.Route.ID || got2.Upstream.ID != got.Upstream.ID {
						t.Fatalf("lookup not deterministic: first %s/%s second %s/%s", got.Route.ID, got.Upstream.ID, got2.Route.ID, got2.Upstream.ID)
					}
				}
			}
		}()
	}
}

func TestSkipChallengeAdversarial(t *testing.T) {
	u := router.Upstream{ID: "u1", Name: "u", URL: "http://127.0.0.1:9"}

	type caseT struct {
		name    string
		routes  []router.Route
		host    string
		rawPath string
		wantOK  bool
		wantID  string
	}

	cases := []caseT{
		{
			name: "path prefix does not match substring",
			routes: []router.Route{
				{ID: "r1", Name: "api", Enabled: true, PathPrefix: "/api", UpstreamID: "u1", Priority: 10, SkipChallenge: true},
				{ID: "r2", Name: "root", Enabled: true, PathPrefix: "/", UpstreamID: "u1", Priority: 0, SkipChallenge: false},
			},
			rawPath: "/apifoo",
			wantOK:  true,
			wantID:  "r2",
		},
		{
			name: "longer prefix wins at same priority",
			routes: []router.Route{
				{ID: "r1", Name: "api", Enabled: true, PathPrefix: "/api", UpstreamID: "u1", Priority: 10, SkipChallenge: true},
				{ID: "r2", Name: "v1", Enabled: true, PathPrefix: "/api/v1", UpstreamID: "u1", Priority: 10, SkipChallenge: false},
			},
			rawPath: "/api/v1/users",
			wantOK:  true,
			wantID:  "r2",
		},
		{
			name: "trailing slash prefix matches path without slash",
			routes: []router.Route{
				{ID: "r1", Name: "api", Enabled: true, PathPrefix: "/api/", UpstreamID: "u1", Priority: 10, SkipChallenge: true},
			},
			rawPath: "/api",
			wantOK:  true,
			wantID:  "r1",
		},
		{
			name: "case sensitive path prefix",
			routes: []router.Route{
				{ID: "r1", Name: "api", Enabled: true, PathPrefix: "/api", UpstreamID: "u1", Priority: 10, SkipChallenge: true},
			},
			rawPath: "/API",
			wantOK:  false,
		},
		{
			name: "percent decoded path matches prefix",
			routes: []router.Route{
				{ID: "r1", Name: "api", Enabled: true, PathPrefix: "/api", UpstreamID: "u1", Priority: 10, SkipChallenge: true},
			},
			rawPath: "/%61pi/v1",
			wantOK:  true,
			wantID:  "r1",
		},
		{
			name: "literal percent in route prefix does not match decoded request",
			routes: []router.Route{
				{ID: "r1", Name: "pct", Enabled: true, PathPrefix: "/%61pi", UpstreamID: "u1", Priority: 10, SkipChallenge: true},
			},
			rawPath: "/%61pi",
			wantOK:  false,
		},
		{
			name: "priority beats prefix length",
			routes: []router.Route{
				{ID: "r1", Name: "root", Enabled: true, PathPrefix: "/", UpstreamID: "u1", Priority: 100, SkipChallenge: false},
				{ID: "r2", Name: "api", Enabled: true, PathPrefix: "/api", UpstreamID: "u1", Priority: 1, SkipChallenge: true},
			},
			rawPath: "/api",
			wantOK:  true,
			wantID:  "r1",
		},
		{
			name: "first input order wins tie",
			routes: []router.Route{
				{ID: "r1", Name: "first", Enabled: true, PathPrefix: "/api", UpstreamID: "u1", Priority: 10, SkipChallenge: true},
				{ID: "r2", Name: "second", Enabled: true, PathPrefix: "/api", UpstreamID: "u1", Priority: 10, SkipChallenge: false},
			},
			rawPath: "/api",
			wantOK:  true,
			wantID:  "r1",
		},
		{
			name: "host with port matches base host",
			routes: []router.Route{
				{ID: "r1", Name: "host", Enabled: true, Hosts: []string{"example.com"}, PathPrefix: "/", UpstreamID: "u1", Priority: 0, SkipChallenge: true},
			},
			host:    "EXAMPLE.COM:443",
			rawPath: "/",
			wantOK:  true,
			wantID:  "r1",
		},
		{
			name: "host mismatch no match",
			routes: []router.Route{
				{ID: "r1", Name: "host", Enabled: true, Hosts: []string{"example.com"}, PathPrefix: "/", UpstreamID: "u1", Priority: 0, SkipChallenge: true},
			},
			host:    "other.test",
			rawPath: "/",
			wantOK:  false,
		},
		{
			name: "subdomain does not match base domain",
			routes: []router.Route{
				{ID: "r1", Name: "host", Enabled: true, Hosts: []string{"example.com"}, PathPrefix: "/", UpstreamID: "u1", Priority: 0, SkipChallenge: true},
			},
			host:    "api.example.com",
			rawPath: "/",
			wantOK:  false,
		},
		{
			name: "IPv6 bracketed request matches unbracketed host",
			routes: []router.Route{
				{ID: "r1", Name: "host", Enabled: true, Hosts: []string{"::1"}, PathPrefix: "/", UpstreamID: "u1", Priority: 0, SkipChallenge: true},
			},
			host:    "[::1]:1234",
			rawPath: "/",
			wantOK:  true,
			wantID:  "r1",
		},
		{
			name: "empty hosts list matches any host",
			routes: []router.Route{
				{ID: "r1", Name: "any", Enabled: true, Hosts: []string{}, PathPrefix: "/", UpstreamID: "u1", Priority: 0, SkipChallenge: true},
			},
			host:    "anything.test:1234",
			rawPath: "/",
			wantOK:  true,
			wantID:  "r1",
		},
		{
			name: "config host with port does not match stripped request",
			routes: []router.Route{
				{ID: "r1", Name: "host", Enabled: true, Hosts: []string{"example.com:8080"}, PathPrefix: "/", UpstreamID: "u1", Priority: 0, SkipChallenge: true},
			},
			host:    "example.com:8080",
			rawPath: "/",
			wantOK:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tab := router.New(t.Context())
			defer tab.Close()
			if err := tab.Replace([]router.Upstream{u}, tc.routes); err != nil {
				t.Fatalf("replace: %v", err)
			}

			// Use httptest.NewRequest so percent-encoded raw paths are decoded
			// exactly as net/http would present them.
			req := httptest.NewRequest(http.MethodGet, "http://example.com"+tc.rawPath, nil)
			req.Host = tc.host

			m, ok := tab.Lookup(req)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v", ok, tc.wantOK)
			}
			if ok && m.Route.ID != tc.wantID {
				t.Fatalf("route id got %q want %q", m.Route.ID, tc.wantID)
			}
			// SkipChallenge must be taken from the matched route.
			if ok {
				wantSkip := false
				for _, r := range tc.routes {
					if r.ID == m.Route.ID {
						wantSkip = r.SkipChallenge
						break
					}
				}
				if m.Route.SkipChallenge != wantSkip {
					t.Fatalf("skip_challenge got %v want %v", m.Route.SkipChallenge, wantSkip)
				}
			}
		})
	}
}

func TestReplaceSameUpstreamIsMetamorphic(t *testing.T) {
	r := rand.New(rand.NewPCG(33, 44))
	ctx := t.Context()

	for range 30 {
		func() {
			tab, upstreams, routes, err := randomTable(ctx, t, r, r.IntN(3)+1, r.IntN(6)+1)
			if err != nil {
				t.Fatalf("replace: %v", err)
			}
			defer tab.Close()

			var reqs []*http.Request
			for range 20 {
				reqs = append(reqs, randomRequest(r, routes))
			}

			first := make(map[string]struct {
				id string
				ok bool
			})
			for _, req := range reqs {
				m, ok := tab.Lookup(req)
				first[keyFor(req)] = struct {
					id string
					ok bool
				}{id: m.Route.ID, ok: ok}
			}

			// Replace with structurally identical upstreams.
			if err := tab.Replace(cloneUpstreams(upstreams), routes); err != nil {
				t.Fatalf("replace with clone: %v", err)
			}

			for _, req := range reqs {
				m, ok := tab.Lookup(req)
				prev := first[keyFor(req)]
				if ok != prev.ok {
					t.Fatalf("ok changed: was %v now %v for host=%q path=%q", prev.ok, ok, req.Host, req.URL.Path)
				}
				if ok && m.Route.ID != prev.id {
					t.Fatalf("route id changed: was %q now %q for host=%q path=%q", prev.id, m.Route.ID, req.Host, req.URL.Path)
				}
			}
		}()
	}
}

func TestDisableRouteRemovesFromAllMatches(t *testing.T) {
	r := rand.New(rand.NewPCG(55, 66))
	ctx := t.Context()

	for range 30 {
		func() {
			tab, upstreams, routes, err := randomTable(ctx, t, r, r.IntN(3)+1, r.IntN(6)+1)
			if err != nil {
				t.Fatalf("replace: %v", err)
			}
			defer tab.Close()

			var reqs []*http.Request
			for range 20 {
				reqs = append(reqs, randomRequest(r, routes))
			}

			for _, disable := range routes {
				disabled := routesWithIDDisabled(routes, disable.ID)
				if err := tab.Replace(upstreams, disabled); err != nil {
					t.Fatalf("replace with disabled %s: %v", disable.ID, err)
				}

				for _, req := range reqs {
					m, ok := tab.Lookup(req)
					if ok && m.Route.ID == disable.ID {
						t.Fatalf("disabled route %s still matched host=%q path=%q", disable.ID, req.Host, req.URL.Path)
					}
					// Also compare with the oracle for the disabled set.
					best, wantOK := referenceBest(upstreams, disabled, req.Host, req.URL.Path)
					if ok != wantOK {
						t.Fatalf("disabled %s: ok=%v want %v for host=%q path=%q", disable.ID, ok, wantOK, req.Host, req.URL.Path)
					}
					if ok && !matchInCandidates(m, best) {
						t.Fatalf("disabled %s: route %s/%s not in best set for host=%q path=%q", disable.ID, m.Route.ID, m.Upstream.ID, req.Host, req.URL.Path)
					}
				}
			}
		}()
	}
}

func keyFor(req *http.Request) string {
	return req.Host + "\x00" + req.URL.Path
}

func TestHealthCheckerLifecycleIsSafe(t *testing.T) {
	ctx := t.Context()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	up := router.Upstream{
		ID:             "u1",
		Name:           "u",
		URL:            origin.URL,
		HealthEnabled:  true,
		HealthInterval: "100ms",
		HealthTimeout:  "100ms",
		HealthPath:     "/health",
	}
	routes := []router.Route{
		{ID: "r1", Name: "r", Enabled: true, PathPrefix: "/", UpstreamID: "u1"},
	}

	tab := router.New(ctx)
	defer tab.Close()

	if err := tab.Replace([]router.Upstream{up}, routes); err != nil {
		t.Fatalf("replace: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, origin.URL+"/", nil)
	if !tab.Healthy(req) {
		t.Fatalf("healthy should be true after first probe")
	}

	// Repeated replace and close of the same table should be lifecycle safe.
	for i := range 5 {
		up2 := up
		up2.SetHeaders = []string{"x-iteration: " + strconv.Itoa(i)}
		if err := tab.Replace([]router.Upstream{up2}, routes); err != nil {
			t.Fatalf("replace %d: %v", i, err)
		}
	}

	if !tab.Healthy(req) {
		t.Fatalf("healthy should be true after repeated replacements")
	}

	// Explicit close while health goroutines are running must not panic.
	tab.Close()

	// A fresh table on the same upstream context can be built and closed.
	tab2 := router.New(ctx)
	defer tab2.Close()
	if err := tab2.Replace([]router.Upstream{up}, routes); err != nil {
		t.Fatalf("replace fresh: %v", err)
	}

	// Give the new health checker at least one probe tick.
	time.Sleep(10 * time.Millisecond)
	if !tab2.Healthy(req) {
		t.Fatalf("healthy should be true on fresh table")
	}
}
