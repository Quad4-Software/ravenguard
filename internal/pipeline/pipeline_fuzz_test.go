// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package pipeline_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/detect"
	"github.com/Quad4-Software/ravenguard/internal/pipeline"
	"github.com/Quad4-Software/ravenguard/internal/ui"
)

func FuzzPipelineChallenge(f *testing.F) {
	cfg := pbtConfig()
	pages, err := ui.New(ui.SiteFromConfig(cfg))
	if err != nil {
		f.Fatal(err)
	}

	f.Add("/", "example.com", "/ws\n/_api", "Upgrade", "websocket", "text/html", true)
	f.Add("/api/v1", "api.example.com", "/api", "keep-alive", "", "text/html", false)
	f.Add("/", "example.com", "", "", "", "application/json", false)

	f.Fuzz(func(t *testing.T, path, host, prefixes, connection, upgrade, accept string, ws bool) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic: %v", r)
			}
		}()

		path = strings.TrimSpace(path)
		host = strings.TrimSpace(host)
		if path == "" {
			path = "/"
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if strings.ContainsAny(path, "\x00\x0d\x0a") {
			t.Skip("control char in path")
		}
		if strings.ContainsAny(host, "\x00\x0d\x0a") {
			t.Skip("control char in host")
		}
		if len(path) > 2048 || len(host) > 256 {
			t.Skip("oversized input")
		}

		target := path
		if host != "" {
			target = "http://" + host + path
		}
		u, err := url.Parse(target)
		if err != nil {
			t.Skipf("parse url: %v", err)
		}

		var req *http.Request
		if ws {
			req = httptest.NewRequest(http.MethodGet, u.EscapedPath(), nil)
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			req.Header.Set("User-Agent", "Mozilla/5.0")
		} else {
			req = httptest.NewRequest(http.MethodGet, u.String(), nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Header.Set("Accept", accept)
			req.Header.Set("Connection", connection)
			req.Header.Set("Upgrade", upgrade)
		}
		req.Host = host
		req.RemoteAddr = "192.0.2.1:1"

		newCfg := pbtConfig()
		newCfg.Challenge.SkipPathPrefixes = splitPrefixes(prefixes)

		for _, p := range newCfg.Challenge.SkipPathPrefixes {
			if p != "" && strings.HasPrefix(p, newCfg.Challenge.PathPrefix) {
				t.Skip("prefix collides with challenge prefix")
			}
		}
		if strings.HasPrefix(req.URL.Path, newCfg.Challenge.PathPrefix) {
			t.Skip("path collides with challenge prefix")
		}

		h := pipeline.New(newCfg, blocklist.New(), nil, nil, pbtChallengeManager(newCfg), pages, pbtUpstream(), nil, nil, nil, testPriv(newCfg), nil, nil)

		// Exercise the handler even on attack-pattern inputs to catch panics,
		// but do not enforce the skip oracle for those inputs.
		if detect.AttackMatch(req) != "" {
			h.ServeHTTP(httptest.NewRecorder(), req)
			return
		}

		want := false
		for _, p := range newCfg.Challenge.SkipPathPrefixes {
			if p != "" && strings.HasPrefix(req.URL.Path, p) {
				want = true
				break
			}
		}

		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		got := responseIsBypass(rr)
		if got != want {
			t.Fatalf("path=%q host=%q prefixes=%q ws=%v want=%v got=%v code=%d body=%q",
				path, host, prefixes, ws, want, got, rr.Code, rr.Body.String())
		}
	})
}

func splitPrefixes(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
