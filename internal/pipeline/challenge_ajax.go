// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package pipeline

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/Quad4-Software/ravenguard/internal/faststr"
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
	if isTopLevelNavigation(r) {
		return true
	}
	accept := r.Header.Get("Accept")
	if faststr.ContainsFold(accept, "text/event-stream") {
		return false
	}
	dest := faststr.TrimSpace(r.Header.Get("Sec-Fetch-Dest"))
	if strings.EqualFold(dest, "document") || strings.EqualFold(dest, "iframe") {
		return true
	}
	if dest != "" {
		// explicit subresource dest (script, style, image, worker, empty, ...)
		return false
	}
	// Legacy clients omit Sec-Fetch-Dest. Fall through to Accept.
	if accept != "" {
		htmlIdx := strings.Index(accept, "text/html")
		jsonIdx := strings.Index(accept, "application/json")
		if jsonIdx >= 0 && (htmlIdx < 0 || jsonIdx < htmlIdx) {
			return false
		}
		if faststr.ContainsFold(accept, "text/event-stream") {
			return false
		}
	}
	return true
}

// isSameOriginRequest reports whether the request originates from the same
// site as the current request host. It trusts Sec-Fetch-Site when present and
// falls back to Origin or Referer for WebSocket, EventSource, and older clients.
func isSameOriginRequest(r *http.Request) bool {
	if r == nil || r.Host == "" {
		return false
	}
	site := faststr.TrimSpace(r.Header.Get("Sec-Fetch-Site"))
	switch {
	case strings.EqualFold(site, "same-origin"), strings.EqualFold(site, "same-site"):
		return true
	case strings.EqualFold(site, "cross-site"), strings.EqualFold(site, "none"):
		return false
	}
	host := stripPort(r.Host)
	for _, hdr := range []string{"Origin", "Referer"} {
		v := faststr.TrimSpace(r.Header.Get(hdr))
		if v == "" {
			continue
		}
		uhost := hostFromURL(v)
		if uhost == "" {
			continue
		}
		if strings.EqualFold(uhost, host) {
			return true
		}
	}
	return false
}

// hostFromURL extracts the host:port from an absolute or protocol-relative
// URL string without allocating. Relative paths have no host and return "".
func hostFromURL(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	} else if strings.HasPrefix(s, "//") {
		s = s[2:]
	} else {
		return ""
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	return stripPort(s)
}

// isBrowserSameOriginSubrequest reports a same-tab fetch/XHR from a page on this origin.
// Those clients cannot render the interstitial. Spoofable, so it only softens detect-mode
// challenges, never always/attack mode.
func isBrowserSameOriginSubrequest(r *http.Request) bool {
	return !wantsHTMLChallenge(r) && isSameOriginRequest(r)
}

// isTopLevelNavigation reports whether the request is a document navigation
// based on Sec-Fetch headers. An absent value is treated as unknown, not true.
func isTopLevelNavigation(r *http.Request) bool {
	dest := faststr.TrimSpace(r.Header.Get("Sec-Fetch-Dest"))
	if strings.EqualFold(dest, "document") || strings.EqualFold(dest, "iframe") {
		return true
	}
	mode := faststr.TrimSpace(r.Header.Get("Sec-Fetch-Mode"))
	return strings.EqualFold(mode, "navigate")
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
