// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package pipeline

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWantsHTMLChallenge(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		hdr  map[string]string
		want bool
	}{
		{
			name: "document navigate",
			hdr: map[string]string{
				"Sec-Fetch-Dest": "document",
				"Accept":         "text/html",
			},
			want: true,
		},
		{
			name: "htmx",
			hdr: map[string]string{
				"HX-Request":     "true",
				"Sec-Fetch-Dest": "empty",
				"Accept":         "text/html",
			},
			want: false,
		},
		{
			name: "xhr",
			hdr: map[string]string{
				"X-Requested-With": "XMLHttpRequest",
				"Accept":           "*/*",
			},
			want: false,
		},
		{
			name: "fetch empty dest",
			hdr: map[string]string{
				"Sec-Fetch-Dest": "empty",
				"Accept":         "*/*",
			},
			want: false,
		},
		{
			name: "json accept",
			hdr: map[string]string{
				"Accept": "application/json",
			},
			want: false,
		},
		{
			name: "legacy browser no sec-fetch",
			hdr: map[string]string{
				"Accept": "text/html,application/xhtml+xml",
			},
			want: true,
		},
		{
			name: "sharedworker script",
			hdr: map[string]string{
				"Sec-Fetch-Dest": "sharedworker",
				"Sec-Fetch-Site": "same-origin",
				"Accept":         "*/*",
			},
			want: false,
		},
		{
			name: "classic script",
			hdr: map[string]string{
				"Sec-Fetch-Dest": "script",
				"Accept":         "*/*",
			},
			want: false,
		},
		{
			name: "eventsource",
			hdr: map[string]string{
				"Accept":         "text/event-stream",
				"Sec-Fetch-Dest": "empty",
				"Sec-Fetch-Site": "same-origin",
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/admin/system_status", nil)
			for k, v := range tc.hdr {
				req.Header.Set(k, v)
			}
			if got := wantsHTMLChallenge(req); got != tc.want {
				t.Fatalf("wantsHTMLChallenge=%v want %v", got, tc.want)
			}
		})
	}
}

func TestSafeNextPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"", "/"},
		{"/admin", "/admin"},
		{"/admin?x=1", "/admin?x=1"},
		{"//evil", "/"},
		{"https://evil", "/"},
		{"/ok\npath", "/"},
		{"/a\\b", "/"},
		{"  /admin  ", "/admin"},
	}
	for _, tc := range cases {
		if got := safeNextPath(tc.in); got != tc.want {
			t.Fatalf("safeNextPath(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestChallengeReturnTo(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/admin/system_status", nil)
	req.Host = "git.example:443"
	req.Header.Set("Referer", "https://git.example/admin")
	if got := challengeReturnTo(req); got != "/admin" {
		t.Fatalf("got %q", got)
	}
	req.Header.Set("Referer", "https://evil.example/admin")
	if got := challengeReturnTo(req); got != "/" {
		t.Fatalf("cross-origin got %q", got)
	}
	req.Header.Del("Referer")
	if got := challengeReturnTo(req); got != "/" {
		t.Fatalf("missing referer got %q", got)
	}
}

func TestIsBrowserSameOriginSubrequest(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/repo/search", nil)
	req.Host = "git.example"
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if !isBrowserSameOriginSubrequest(req) {
		t.Fatal("expected same-origin fetch")
	}
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if isBrowserSameOriginSubrequest(req) {
		t.Fatal("cross-site must not count")
	}
	req.Header.Del("Sec-Fetch-Site")
	req.Header.Set("Referer", "https://git.example/")
	if !isBrowserSameOriginSubrequest(req) {
		t.Fatal("same-host referer should count when sec-fetch-site absent")
	}
	doc := httptest.NewRequest(http.MethodGet, "/", nil)
	doc.Header.Set("Sec-Fetch-Dest", "document")
	if isBrowserSameOriginSubrequest(doc) {
		t.Fatal("documents are not subrequests")
	}
}
