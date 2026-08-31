// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ui_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/ui"
)

func TestRenderPages(t *testing.T) {
	pages, err := ui.New(ui.Site{Brand: "RavenGuard", StatusText: "Checking", Prefix: "/_rg"})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		fn   func(http.ResponseWriter)
		code int
		want string
	}{
		{"block", func(w http.ResponseWriter) { pages.RenderBlock(w, "ray1", "IP blocked") }, 403, "Access denied"},
		{"rate", func(w http.ResponseWriter) { pages.RenderRateLimit(w, "ray2") }, 429, "Too many requests"},
		{"up", func(w http.ResponseWriter) { pages.RenderUpstream(w, "ray3") }, 502, "Origin unreachable"},
		{"err", func(w http.ResponseWriter) {
			pages.RenderError(w, "ray4", "Internal error", "boom", 500)
		}, 500, "Internal error"},
		{"test", func(w http.ResponseWriter) { pages.RenderTestIndex(w, "ray5") }, 200, "UI preview"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			tc.fn(rr)
			if rr.Code != tc.code {
				t.Fatalf("code=%d want %d", rr.Code, tc.code)
			}
			body := rr.Body.String()
			if !strings.Contains(body, tc.want) {
				t.Fatalf("missing %q in %s", tc.want, body[:min(180, len(body))])
			}
			if !strings.Contains(body, "raven.png") {
				t.Fatal("missing raven")
			}
			if !strings.Contains(body, `name="robots"`) {
				t.Fatal("missing robots meta")
			}
			if !strings.Contains(body, "favicon.ico") {
				t.Fatal("missing favicon")
			}
			if !strings.Contains(body, "Ray ID") {
				t.Fatal("missing ray")
			}
		})
	}
}

func TestStaticNoListingAndRootFavicon(t *testing.T) {
	pages, err := ui.New(ui.Site{Brand: "RavenGuard", StatusText: "Checking", Prefix: "/_rg"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	pages.MountStaticTo(mux, "/_rg/test")

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/_rg/static/", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("dir code=%d want redirect", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/_rg/test" {
		t.Fatalf("location=%q", loc)
	}

	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/_rg/static/challenge.css", nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("css code=%d", rr2.Code)
	}
	if rr2.Body.Len() == 0 {
		t.Fatal("empty css")
	}

	rr3 := httptest.NewRecorder()
	mux.ServeHTTP(rr3, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))
	if rr3.Code != http.StatusOK {
		t.Fatalf("favicon code=%d", rr3.Code)
	}
	if rr3.Body.Len() == 0 {
		t.Fatal("empty favicon")
	}
}
