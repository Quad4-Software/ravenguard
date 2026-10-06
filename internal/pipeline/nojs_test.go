// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package pipeline_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/config"
)

func lynxHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Lynx/2.9.2 libwww-FM/2.14 SSL-MM/1.4.1")
	req.Header.Set("Accept", "text/html")
}

func TestNoJSChallengeLinkAndClearance(t *testing.T) {
	h := forgeTestHandler(t, nil)

	// A text browser on a forge-hot path is challenged, and the page offers
	// the noscript continue link.
	req := httptest.NewRequest(http.MethodGet, "/repo/snapshot/x.tar.gz", nil)
	lynxHeaders(req)
	req.RemoteAddr = "192.0.2.220:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("text browser on hot path should be challenged")
	}
	body := rr.Body.String()
	if !strings.Contains(body, `noscript`) || !strings.Contains(body, "/_rg/noscript?next=") {
		t.Fatalf("challenge page missing no-js continue link: %s", body[:min(400, len(body))])
	}

	// The endpoint mints a clearance cookie and redirects.
	req = httptest.NewRequest(http.MethodGet, "/_rg/noscript?next=/repo/snapshot/x.tar.gz", nil)
	lynxHeaders(req)
	req.RemoteAddr = "192.0.2.220:1"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("noscript get: code=%d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/repo/snapshot/x.tar.gz" {
		t.Fatalf("noscript redirect=%q", loc)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("noscript did not set a clearance cookie")
	}

	// The cleared text browser now passes the hot path.
	req = httptest.NewRequest(http.MethodGet, "/repo/snapshot/x.tar.gz", nil)
	lynxHeaders(req)
	req.RemoteAddr = "192.0.2.220:1"
	req.AddCookie(cookies[0])
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("cleared text browser should pass, got %d", rr.Code)
	}
}

func TestNoScriptRejectsBrowserUAs(t *testing.T) {
	h := forgeTestHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/_rg/noscript?next=/x", nil)
	forgeBrowserHeaders(req)
	req.RemoteAddr = "192.0.2.221:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("browser UA on noscript should get 403, got %d", rr.Code)
	}
	if len(rr.Result().Cookies()) != 0 {
		t.Fatal("no cookie should be set for browser UAs")
	}
}

func TestNoScriptDisabledByConfig(t *testing.T) {
	h := forgeTestHandler(t, func(cfg *config.Config) {
		cfg.Challenge.NoJSFallback = false
	})
	req := httptest.NewRequest(http.MethodGet, "/_rg/noscript?next=/x", nil)
	lynxHeaders(req)
	req.RemoteAddr = "192.0.2.222:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusSeeOther {
		t.Fatal("noscript should be disabled")
	}
	req = httptest.NewRequest(http.MethodGet, "/repo/snapshot/x.tar.gz", nil)
	lynxHeaders(req)
	req.RemoteAddr = "192.0.2.223:1"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if strings.Contains(rr.Body.String(), "noscript?next=") {
		t.Fatal("no-js link rendered while disabled")
	}
}
