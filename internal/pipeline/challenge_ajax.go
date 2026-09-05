// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package pipeline

import (
	"net/http"
	"net/url"
	"strings"
)

// wantsHTMLChallenge reports whether this request should receive the full
// interstitial HTML. HTMX, XHR, fetch, and JSON clients get a compact
// challenge response instead so fragments and APIs are not replaced by the gate page.
func wantsHTMLChallenge(r *http.Request) bool {
	if r.Header.Get("HX-Request") != "" {
		return false
	}
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return false
	}
	dest := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest")))
	switch dest {
	case "document", "iframe":
		return true
	case "empty", "worker", "sharedworker":
		return false
	}
	accept := r.Header.Get("Accept")
	if accept != "" {
		htmlIdx := strings.Index(accept, "text/html")
		jsonIdx := strings.Index(accept, "application/json")
		if jsonIdx >= 0 && (htmlIdx < 0 || jsonIdx < htmlIdx) {
			return false
		}
	}
	return true
}

// safeNextPath returns a same-origin relative path suitable for post-challenge redirect.
func safeNextPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "/"
	}
	if strings.ContainsAny(raw, "\r\n\\") {
		return "/"
	}
	return raw
}

// challengeReturnTo picks a navigable page for AJAX clients that need the gate.
// Prefer the same-origin Referer so HTMX polls redirect to the page the user is viewing.
func challengeReturnTo(r *http.Request) string {
	ref := strings.TrimSpace(r.Header.Get("Referer"))
	if ref == "" {
		return "/"
	}
	u, err := url.Parse(ref)
	if err != nil {
		return "/"
	}
	if u.Host != "" && !strings.EqualFold(stripPort(u.Host), stripPort(r.Host)) {
		return "/"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return safeNextPath(path)
}
