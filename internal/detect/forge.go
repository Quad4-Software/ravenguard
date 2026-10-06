// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package detect

// ForgeClass classifies forge repository paths by cost.
type ForgeClass int

const (
	// ForgeNone is not a forge expensive or browse path.
	ForgeNone ForgeClass = iota
	// ForgeBrowse is normal code browsing (src, raw, tree, commit) scored only via burst.
	ForgeBrowse
	// ForgeHot is scraper-hot (compare, blame, archive, snapshot, diff) and scores per request.
	ForgeHot
)

// ForgeFlavor selects which forge layouts Classify understands.
type ForgeFlavor int

const (
	// ForgeAuto covers Gitea/Forgejo owner/repo/action paths plus cgit
	// repo/cmd paths where the command sits in the first two segments.
	ForgeAuto ForgeFlavor = iota
	// ForgeGitea limits detection to Gitea/Forgejo layouts.
	ForgeGitea
	// ForgeCgit scans every segment for a cgit command, which suits cgit
	// deployments that nest repos under group directories.
	ForgeCgit
)

// ParseForgeFlavor maps a config string to a ForgeFlavor. Unknown or empty
// values select ForgeAuto.
func ParseForgeFlavor(s string) ForgeFlavor {
	switch {
	case eqFoldASCII(s, "gitea") || eqFoldASCII(s, "forgejo"):
		return ForgeGitea
	case eqFoldASCII(s, "cgit"):
		return ForgeCgit
	}
	return ForgeAuto
}

// ForgePathClass returns the cost tier for a URL path under ForgeAuto.
func ForgePathClass(path string) ForgeClass {
	return ForgeAuto.Classify(path)
}

// Classify returns the cost tier for a URL path under this flavor.
// Zero allocations. Skips git smart-HTTP.
func (f ForgeFlavor) Classify(path string) ForgeClass {
	if path == "" || path == "/" {
		return ForgeNone
	}
	if isSmartHTTPPath(path) {
		return ForgeNone
	}

	if f != ForgeCgit {
		// Gitea/Forgejo: /{owner}/{repo}/{action} and
		// /api/vN/repos/{owner}/{repo}/{action}.
		if action, next := forgeActionSeg(path); action != "" {
			if eqFoldASCII(action, "git") {
				if eqFoldASCII(next, "trees") || eqFoldASCII(next, "blobs") {
					return ForgeHot
				}
			} else if cls := classifyForgeAction(action); cls != ForgeNone {
				return cls
			} else if cls := classifyCgitCmd(action); cls != ForgeNone {
				// Auto also accepts a cgit command at the action position so
				// one-level nested cgit repos (/{group}/{repo}/{cmd}) score.
				return cls
			}
		}
		if f == ForgeGitea {
			return ForgeNone
		}
		// Flat cgit layout: /{repo}/{cmd}.
		if _, rest := nextSeg(skipLeadSlash(path)); rest != "" {
			if cmd, _ := nextSeg(rest); cmd != "" {
				if cls := classifyCgitCmd(cmd); cls != ForgeNone {
					return cls
				}
			}
		}
		return ForgeNone
	}

	// cgit nests repos arbitrarily deep, so any segment may carry the command.
	rest := path
	for rest != "" {
		var seg string
		seg, rest = nextSeg(rest)
		if seg == "" {
			continue
		}
		if cls := classifyCgitCmd(seg); cls != ForgeNone {
			return cls
		}
	}
	return ForgeNone
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

func skipLeadSlash(p string) string {
	if p != "" && p[0] == '/' {
		return p[1:]
	}
	return p
}

func forgeActionSeg(path string) (action, next string) {
	p := skipLeadSlash(path)
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

// classifyForgeAction is the Gitea/Forgejo action table.
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

// classifyCgitCmd is the cgit command table. cgit commands sit at
// /{repo}/{cmd}/... in virtual-root layouts.
func classifyCgitCmd(seg string) ForgeClass {
	switch len(seg) {
	case 3:
		if eqFoldASCII(seg, "log") || eqFoldASCII(seg, "tag") || eqFoldASCII(seg, "ref") {
			return ForgeBrowse
		}
	case 4:
		if eqFoldASCII(seg, "tree") || eqFoldASCII(seg, "blob") || eqFoldASCII(seg, "atom") || eqFoldASCII(seg, "refs") {
			return ForgeBrowse
		}
		if eqFoldASCII(seg, "diff") {
			return ForgeHot
		}
	case 5:
		if eqFoldASCII(seg, "plain") || eqFoldASCII(seg, "about") || eqFoldASCII(seg, "clone") || eqFoldASCII(seg, "graph") || eqFoldASCII(seg, "stats") {
			return ForgeBrowse
		}
		if eqFoldASCII(seg, "blame") || eqFoldASCII(seg, "patch") {
			return ForgeHot
		}
	case 6:
		if eqFoldASCII(seg, "commit") || eqFoldASCII(seg, "branch") {
			return ForgeBrowse
		}
	case 7:
		if eqFoldASCII(seg, "summary") {
			return ForgeBrowse
		}
	case 8:
		if eqFoldASCII(seg, "snapshot") {
			return ForgeHot
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
