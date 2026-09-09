// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package router_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/router"
)

// FuzzMatchPrefix exercises route matching with an implicit oracle.
//
// Invariants checked for every generated input:
//   - Table.Lookup never panics.
//   - The result is deterministic: two lookups for the same request agree.
//   - The matched route, if any, is one of the best candidates by priority
//     and prefix length.
//   - A disabled or non-matching route is never returned.
func FuzzMatchPrefix(f *testing.F) {
	f.Add("/", "/", "/", 0, 0, false, false)
	f.Add("/api", "/api", "/", 10, 0, true, false)
	f.Add("/api/v1", "/api", "/api/v1", 10, 10, false, false)
	f.Add("/apifoo", "/api", "/", 10, 0, true, false)
	f.Add("/%61pi", "/api", "/", 10, 0, true, false)
	f.Add("/foo%20bar", "/foo bar", "/", 10, 0, true, false)
	f.Add("/api", "/API", "/", 10, 0, true, false)

	f.Fuzz(func(t *testing.T, path, prefix1, prefix2 string, p1, p2 int, skip1, skip2 bool) {
		up := router.Upstream{ID: "u1", Name: "u", URL: "http://127.0.0.1:9"}
		routes := []router.Route{
			{
				ID:            "r1",
				Name:          "r1",
				Enabled:       true,
				PathPrefix:    prefix1,
				UpstreamID:    "u1",
				Priority:      p1,
				SkipChallenge: skip1,
			},
			{
				ID:            "r2",
				Name:          "r2",
				Enabled:       true,
				PathPrefix:    prefix2,
				UpstreamID:    "u1",
				Priority:      p2,
				SkipChallenge: skip2,
			},
		}

		tab := router.New(t.Context())
		defer tab.Close()

		if err := tab.Replace([]router.Upstream{up}, routes); err != nil {
			t.Fatalf("replace: %v", err)
		}

		// Build the request safely from arbitrary fuzz input.
		raw := "http://example.com" + path
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			u = &url.URL{Scheme: "http", Host: "example.com", Path: path}
		}
		if u.Path == "" {
			u.Path = "/"
		}
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.URL = u
		req.Host = u.Host

		got, ok := tab.Lookup(req)

		// Implicit best-match oracle: no panic and a deterministic result.
		got2, ok2 := tab.Lookup(req)
		if ok != ok2 {
			t.Fatalf("lookup ok not deterministic: %v vs %v", ok, ok2)
		}
		if ok {
			if got.Route.ID != got2.Route.ID || got.Upstream.ID != got2.Upstream.ID {
				t.Fatalf("lookup not deterministic: %s/%s vs %s/%s", got.Route.ID, got.Upstream.ID, got2.Route.ID, got2.Upstream.ID)
			}
		}

		best, wantOK := referenceBest([]router.Upstream{up}, routes, req.Host, req.URL.Path)
		if ok != wantOK {
			t.Fatalf("ok=%v want %v for path=%q prefixes=%q/%q priorities=%d/%d", ok, wantOK, path, prefix1, prefix2, p1, p2)
		}
		if ok && !matchInCandidates(got, best) {
			t.Fatalf("route %s/%s not in best set for path=%q prefixes=%q/%q priorities=%d/%d", got.Route.ID, got.Upstream.ID, path, prefix1, prefix2, p1, p2)
		}

		// A matched route must actually match the request path and host.
		if ok {
			var matchedRoute router.Route
			for _, r := range routes {
				if r.ID == got.Route.ID {
					matchedRoute = r
					break
				}
			}
			prefix := matchedRoute.PathPrefix
			if prefix == "" {
				prefix = "/"
			}
			if !strings.HasPrefix(prefix, "/") {
				prefix = "/" + prefix
			}
			if !matchPrefixOracle(req.URL.Path, prefix) {
				t.Fatalf("route %s path %q does not match prefix %q", matchedRoute.ID, req.URL.Path, prefix)
			}
			if got.Route.SkipChallenge != matchedRoute.SkipChallenge {
				t.Fatalf("skip_challenge changed from %v to %v", matchedRoute.SkipChallenge, got.Route.SkipChallenge)
			}
		}
	})
}
