// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package pipeline

import (
	"net/http"
	"net/url"
	"strings"
)

// wantsHTMLChallenge reports whether this request should receive the full
// interstitial HTML. Only top-level documents (and iframes) can render it.
// Scripts, workers, EventSource, XHR, and other subresources get a compact
// response or (in detect mode) a soft pass so SPAs like Forgejo keep working.
func wantsHTMLChallenge(r *http.Request) bool {
	if r.Header.Get("HX-Request") != "" {
		return false
	}
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return false
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream") {
		return false
	}
	dest := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest")))
	switch dest {
	case "document", "iframe":
		return true
	case "":
		// Legacy clients omit Sec-Fetch-Dest. Fall through to Accept.
	default:
		// script, style, image, font, worker, sharedworker, empty, ...
		return false
	}
	accept := r.Header.Get("Accept")
	if accept != "" {
		htmlIdx := strings.Index(accept, "text/html")
		jsonIdx := strings.Index(accept, "application/json")
		if jsonIdx >= 0 && (htmlIdx < 0 || jsonIdx < htmlIdx) {
			return false
		}
		if strings.Contains(accept, "text/event-stream") {
			return false
		}
	}
	return true
}

func isEventSourceRequest(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")
}

// isBrowserSameOriginSubrequest reports a same-tab fetch/XHR from a page on this origin.
// Those clients cannot render the interstitial. Spoofable, so it only softens detect-mode
// challenges, never always/attack mode.
func isBrowserSameOriginSubrequest(r *http.Request) bool {
	if wantsHTMLChallenge(r) {
		return false
	}
	site := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")))
	switch site {
	case "same-origin", "same-site":
		return true
	case "cross-site", "none":
		return false
	}
	// Older browsers omit Sec-Fetch-Site. Treat same-origin Referer as a subrequest hint.
	ref := strings.TrimSpace(r.Header.Get("Referer"))
	if ref == "" {
		return false
	}
	u, err := url.Parse(ref)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(stripPort(u.Host), stripPort(r.Host))
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
