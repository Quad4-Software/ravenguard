// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ui_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/ui"
)

func testSite() ui.Site {
	return ui.Site{
		Brand:          "RavenGuard",
		StatusText:     "Checking",
		Prefix:         "/_rg",
		ServeRootIcons: true,
		ServeManifest:  true,
	}
}

func TestRenderPages(t *testing.T) {
	pages, err := ui.New(testSite())
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
			if !strings.Contains(body, "c.css") {
				t.Fatal("missing challenge css asset")
			}
		})
	}
}

func TestStaticNoListingAndRootFavicon(t *testing.T) {
	pages, err := ui.New(testSite())
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
	mux.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/_rg/static/c.css", nil))
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

func TestServeRootIconsOff(t *testing.T) {
	site := testSite()
	site.ServeRootIcons = false
	pages, err := ui.New(site)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	pages.MountStaticTo(mux, "")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code=%d want 404", rr.Code)
	}
}

func TestUpdateSiteAndAccessForm(t *testing.T) {
	pages, err := ui.New(testSite())
	if err != nil {
		t.Fatal(err)
	}
	pages.UpdateSite(ui.Site{
		Brand:          "Gate",
		Prefix:         "/_rg",
		FooterText:     "Protected",
		HideBrandMark:  true,
		GenericCopy:    true,
		Background:     "#111111",
		ServeRootIcons: true,
		BlockTitle:     "Denied",
	})
	site := pages.Site()
	if site.Brand != "Gate" || site.RayLabel != "Ref" || site.ChallengeTitle != "VERIFY" {
		t.Fatalf("site=%+v", site)
	}

	rr := httptest.NewRecorder()
	pages.RenderBlock(rr, "r1", "nope")
	body := rr.Body.String()
	if !strings.Contains(body, "Denied") {
		t.Fatal("missing block title")
	}
	if strings.Contains(body, "raven.png") {
		t.Fatal("brand mark should be hidden")
	}
	if !strings.Contains(body, "Ref:") {
		t.Fatal("missing generic ray label")
	}
	if !strings.Contains(body, "--bg: #111111") {
		t.Fatal("missing theme var")
	}

	rr2 := httptest.NewRecorder()
	pages.ServeAccessForm(rr2, "pin", "/_rg/access")
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rr2.Code)
	}
	ab := rr2.Body.String()
	if !strings.Contains(ab, `name="pin"`) {
		t.Fatal("missing pin input")
	}
	if !strings.Contains(ab, "Protected") {
		t.Fatal("missing footer")
	}
}

func TestSiteFromConfig(t *testing.T) {
	cfg := config.Default()
	cfg.UI.Brand = "Acme"
	cfg.UI.LogoURL = "https://cdn.example/logo.svg"
	cfg.UI.CustomCSS = "body{outline:1px solid red}"
	cfg.UI.Contact = "help@example.com"
	cfg.Stealth.GenericCopy = true
	cfg.Stealth.HideBrandMark = true
	cfg.Stealth.ElementName = "acme-check"
	cfg.Challenge.PathPrefix = "/x"
	site := ui.SiteFromConfig(cfg)
	if site.Brand != "Acme" || site.Prefix != "/x" || site.ElementName != "acme-check" {
		t.Fatalf("site=%+v", site)
	}
	if site.Contact != "help@example.com" {
		t.Fatalf("contact=%q", site.Contact)
	}
	if string(site.CustomCSS) != cfg.UI.CustomCSS {
		t.Fatal("custom css")
	}
	pages, err := ui.New(site)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	pages.ServeChallenge(rr, ui.Data{RayID: "abc", ChallengeURL: "/x/v1/challenge", Gate: "interactive"})
	body := rr.Body.String()
	if !strings.Contains(body, "VERIFY") {
		t.Fatal("missing verify title")
	}
	if !strings.Contains(body, "acme-check") {
		t.Fatal("missing element name")
	}
	if !strings.Contains(body, `auto="off"`) {
		t.Fatal("expected interactive auto=off")
	}
	if !strings.Contains(body, "https://cdn.example/logo.svg") {
		t.Fatal("missing logo url")
	}
	if !strings.Contains(body, "w.js") || !strings.Contains(body, "c.js") {
		t.Fatal("missing neutral asset names")
	}

	rr2 := httptest.NewRecorder()
	pages.ServeChallenge(rr2, ui.Data{RayID: "inv", ChallengeURL: "/x/v1/challenge", Gate: "invisible"})
	body2 := rr2.Body.String()
	if !strings.Contains(body2, `auto="onload"`) || !strings.Contains(body2, `display="invisible"`) {
		t.Fatal("expected invisible widget attrs")
	}
	if !strings.Contains(body2, `window["__g__"]`) {
		t.Fatalf("bootstrap global missing or double-escaped: %s", body2[strings.Index(body2, "window"):])
	}
	if strings.Contains(body2, `window["\"__g__\""]`) {
		t.Fatal("bootstrap global is double-escaped")
	}

	rr3 := httptest.NewRecorder()
	pages.RenderBlock(rr3, "ray-c", "blocked")
	block := rr3.Body.String()
	if !strings.Contains(block, `href="mailto:help@example.com"`) {
		t.Fatalf("missing contact mailto: %s", block[:min(300, len(block))])
	}
}

func TestBlockContactVariants(t *testing.T) {
	cases := []struct {
		name    string
		contact string
		want    string
		noHref  bool
	}{
		{"email", "ops@example.com", `href="mailto:ops@example.com"`, false},
		{"mailto", "mailto:ops@example.com", `href="mailto:ops@example.com"`, false},
		{"https", "https://help.example.com/ticket", `href="https://help.example.com/ticket"`, false},
		{"phone", "+15550101234", `href="tel:&#43;15550101234"`, false},
		{"tel", "tel:+15550101234", `href="tel:&#43;15550101234"`, false},
		{"plain", "Ask your network admin", "Ask your network admin", true},
		{"js", "javascript:alert(1)", "javascript:alert(1)", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			site := testSite()
			site.Contact = tc.contact
			pages, err := ui.New(site)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			pages.RenderBlock(rr, "r", "denied")
			body := rr.Body.String()
			if tc.noHref {
				if strings.Contains(body, `href="javascript:`) {
					t.Fatal("javascript href must not render")
				}
				if strings.Contains(body, `<a href=`) {
					t.Fatalf("unexpected contact link: %s", body[:min(400, len(body))])
				}
				if !strings.Contains(body, tc.contact) {
					t.Fatalf("missing plain contact text in %s", body[:min(400, len(body))])
				}
			} else if !strings.Contains(body, tc.want) {
				t.Fatalf("missing %q in %s", tc.want, body[:min(400, len(body))])
			}
		})
	}
}
