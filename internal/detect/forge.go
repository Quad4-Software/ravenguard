// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect

// ForgeClass classifies Gitea/Forgejo-family repository paths by cost.
type ForgeClass int

const (
	// ForgeNone is not a forge expensive or browse path.
	ForgeNone ForgeClass = iota
	// ForgeBrowse is normal code browsing (src, raw, commit) scored only via burst.
	ForgeBrowse
	// ForgeHot is scraper-hot (compare, blame, archive) and scores per request.
	ForgeHot
)

// ForgePathClass returns the cost tier for a URL path.
// Zero allocations. Segment-aware for /{owner}/{repo}/action and
// /api/vN/repos/{owner}/{repo}/action. Skips git smart-HTTP.
func ForgePathClass(path string) ForgeClass {
	if path == "" || path == "/" {
		return ForgeNone
	}
	if isSmartHTTPPath(path) {
		return ForgeNone
	}

	action, next := forgeActionSeg(path)
	if action == "" {
		return ForgeNone
	}
	if eqFoldASCII(action, "git") {
		if eqFoldASCII(next, "trees") || eqFoldASCII(next, "blobs") {
			return ForgeHot
		}
		return ForgeNone
	}
	return classifyForgeAction(action)
}

func isSmartHTTPPath(path string) bool {
	return hasPathSuffix(path, "/info/refs") ||
		hasPathSuffix(path, "/git-upload-pack") ||
		hasPathSuffix(path, "/git-receive-pack")
}

func hasPathSuffix(path, suffix string) bool {
	n, m := len(path), len(suffix)
	if n < m {
		return false
	}
	for i := range m {
		if path[n-m+i] != suffix[i] {
			return false
		}
	}
	return true
}

func forgeActionSeg(path string) (action, next string) {
	p := path
	if p[0] == '/' {
		p = p[1:]
	}
	if p == "" {
		return "", ""
	}

	if len(p) >= 6 && eqFoldASCII(p[:4], "api/") && (p[4] == 'v' || p[4] == 'V') {
		i := 5
		for i < len(p) && p[i] >= '0' && p[i] <= '9' {
			i++
		}
		if i > 5 && i+7 <= len(p) && p[i] == '/' && eqFoldASCII(p[i+1:i+6], "repos") && (i+6 == len(p) || p[i+6] == '/') {
			p = p[i+7:]
			if len(p) > 0 && p[0] == '/' {
				p = p[1:]
			}
		}
	}

	seg0, rest := nextSeg(p)
	if seg0 == "" || rest == "" {
		return "", ""
	}
	seg1, rest := nextSeg(rest)
	if seg1 == "" || rest == "" {
		return "", ""
	}
	action, rest = nextSeg(rest)
	if action == "" {
		return "", ""
	}
	next, _ = nextSeg(rest)
	return action, next
}

func nextSeg(p string) (seg, rest string) {
	if p == "" {
		return "", ""
	}
	if p[0] == '/' {
		p = p[1:]
	}
	if p == "" {
		return "", ""
	}
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			return p[:i], p[i+1:]
		}
	}
	return p, ""
}

func classifyForgeAction(seg string) ForgeClass {
	switch len(seg) {
	case 3:
		if eqFoldASCII(seg, "src") || eqFoldASCII(seg, "raw") {
			return ForgeBrowse
		}
	case 5:
		if eqFoldASCII(seg, "blame") {
			return ForgeHot
		}
		if eqFoldASCII(seg, "media") {
			return ForgeBrowse
		}
	case 6:
		if eqFoldASCII(seg, "commit") {
			return ForgeBrowse
		}
	case 7:
		if eqFoldASCII(seg, "compare") || eqFoldASCII(seg, "archive") {
			return ForgeHot
		}
		if eqFoldASCII(seg, "commits") {
			return ForgeBrowse
		}
	}
	return ForgeNone
}

func eqFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
