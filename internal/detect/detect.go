// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect

import (
	"net/http"
	"strconv"
	"sync"

	"github.com/Quad4-Software/ravenguard/internal/faststr"
)

type Config struct {
	MissingUAScore         int
	ScannerUAScore         int
	AIUAScore              int
	ProbePathScore         int
	OddMethodScore         int
	MissingAcceptScore     int
	MissingAcceptLangScore int
	MissingSecFetchScore   int
	SecCHUAMismatchScore   int
	StarAcceptBrowserScore int
	ProxyBotLowScore       int
	ProxyBotHeader         string
	ProxyBotScoreHeader    string
	ProxyJA4Header         string
}

type Result struct {
	Score   int
	Reasons []string
}

var scannerUA = []string{
	"sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster",
	"gobuster", "wfuzz", "ffuf", "nuclei", "httpx", "acunetix",
	"nessus", "openvas", "w3af", "burpsuite", "python-requests",
	"go-http-client", "scrapy", "curl/", "wget/", "libwww-perl",
	"java/", "phantomjs", "headlesschrome", "semrush", "ahrefs",
	"mj12bot", "dotbot", "petalbot",
}

var aiUA = []string{
	"gptbot", "chatgpt-user", "oai-searchbot", "claudebot", "claude-web",
	"anthropic-ai", "bytespider", "ccbot", "google-extended",
	"meta-externalagent", "meta-externalfetcher", "perplexitybot",
	"amazonbot", "cohere-ai", "ai2bot", "diffbot", "youbot",
	"omgili", "facebookexternalhit", "imagesiftbot",
}

var probePaths = []string{
	"/.env", "/wp-admin", "/wp-login", "/xmlrpc.php", "/phpmyadmin",
	"/.git", "/admin", "/actuator", "/server-status", "/cgi-bin",
	"/vendor/phpunit", "/etc/passwd", "/.aws", "/api/v1/admin",
	"/console", "/manager/html", "/owa/", "/hnap1",
}

var lowerPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 256)
		return &b
	},
}

func Score(r *http.Request, cfg Config) Result {
	return score(r, cfg, false)
}

// ScoreDebug is Score with reason strings for diagnostics and tests.
func ScoreDebug(r *http.Request, cfg Config) Result {
	return score(r, cfg, true)
}

func score(r *http.Request, cfg Config, wantReasons bool) Result {
	var res Result
	ua := r.Header.Get("User-Agent")

	var lowUA []byte
	var lowUAPtr *[]byte
	if ua != "" {
		lowUAPtr = lowerPool.Get().(*[]byte)
		lowUA = faststr.AppendLowerASCII((*lowUAPtr)[:0], ua)
	}

	if ua == "" {
		res.Score += cfg.MissingUAScore
		if wantReasons {
			res.Reasons = append(res.Reasons, "missing_ua")
		}
	} else {
		if matchAnyBytes(lowUA, scannerUA) {
			res.Score += cfg.ScannerUAScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "scanner_ua")
			}
		}
		if matchAnyBytes(lowUA, aiUA) {
			score := cfg.AIUAScore
			if score <= 0 {
				score = cfg.ScannerUAScore
			}
			res.Score += score
			if wantReasons {
				res.Reasons = append(res.Reasons, "ai_ua")
			}
		}
	}

	accept := r.Header.Get("Accept")
	if accept == "" {
		res.Score += cfg.MissingAcceptScore
		if wantReasons {
			res.Reasons = append(res.Reasons, "missing_accept")
		}
	}

	if looksBrowserBytes(lowUA) {
		if r.Header.Get("Accept-Language") == "" && cfg.MissingAcceptLangScore > 0 {
			res.Score += cfg.MissingAcceptLangScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "missing_accept_lang")
			}
		}
		if isDocumentGET(r) && missingSecFetch(r) && cfg.MissingSecFetchScore > 0 {
			res.Score += cfg.MissingSecFetchScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "missing_sec_fetch")
			}
		}
		if secCHUAMismatchBytes(r, lowUA) && cfg.SecCHUAMismatchScore > 0 {
			res.Score += cfg.SecCHUAMismatchScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "sec_ch_ua_mismatch")
			}
		}
		if accept == "*/*" && isDocumentPath(r.URL.Path) && cfg.StarAcceptBrowserScore > 0 {
			res.Score += cfg.StarAcceptBrowserScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "star_accept_browser")
			}
		}
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
	default:
		res.Score += cfg.OddMethodScore
		if wantReasons {
			res.Reasons = append(res.Reasons, "odd_method")
		}
	}

	path := r.URL.Path
	for _, p := range probePaths {
		if faststr.HasPrefixFold(path, p) || faststr.ContainsFold(path, p) {
			res.Score += cfg.ProbePathScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "probe_path")
			}
			break
		}
	}

	if lowUAPtr != nil {
		*lowUAPtr = lowUA[:0]
		lowerPool.Put(lowUAPtr)
	}

	scoreProxySignals(r, cfg, &res, wantReasons)
	return res
}

func scoreProxySignals(r *http.Request, cfg Config, res *Result, wantReasons bool) {
	if cfg.ProxyBotLowScore <= 0 {
		return
	}
	if h := cfg.ProxyBotHeader; h != "" {
		if scoreProxyHeader(r, h, cfg, res, wantReasons) {
			return
		}
	}
	if h := cfg.ProxyBotScoreHeader; h != "" {
		_ = scoreProxyHeader(r, h, cfg, res, wantReasons)
	}
}

func scoreProxyHeader(r *http.Request, h string, cfg Config, res *Result, wantReasons bool) bool {
	raw := faststr.TrimSpace(r.Header.Get(h))
	if raw == "" {
		return false
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return false
	}
	if n > 0 && n < 30 {
		res.Score += cfg.ProxyBotLowScore
		if wantReasons {
			res.Reasons = append(res.Reasons, "proxy_bot_score")
		}
		return true
	}
	return false
}

func matchAnyBytes(low []byte, pats []string) bool {
	for _, p := range pats {
		if faststr.ContainsBytes(low, p) {
			return true
		}
	}
	return false
}

func matchAnyFold(s string, pats []string) bool {
	if s == "" {
		return false
	}
	bp := lowerPool.Get().(*[]byte)
	low := faststr.AppendLowerASCII((*bp)[:0], s)
	ok := matchAnyBytes(low, pats)
	*bp = low[:0]
	lowerPool.Put(bp)
	return ok
}

func looksBrowserBytes(low []byte) bool {
	if len(low) == 0 {
		return false
	}
	return faststr.ContainsBytes(low, "mozilla/") ||
		faststr.ContainsBytes(low, "chrome/") ||
		faststr.ContainsBytes(low, "safari/") ||
		faststr.ContainsBytes(low, "firefox/") ||
		faststr.ContainsBytes(low, "edg/")
}

func isDocumentGET(r *http.Request) bool {
	return r.Method == http.MethodGet && isDocumentPath(r.URL.Path)
}

func isDocumentPath(path string) bool {
	if path == "" || path == "/" {
		return true
	}
	dot := -1
	for i := len(path) - 1; i >= 0; i-- {
		c := path[i]
		if c == '/' {
			break
		}
		if c == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return true
	}
	ext := path[dot:]
	switch {
	case equalFoldExt(ext, ".html"), equalFoldExt(ext, ".htm"), equalFoldExt(ext, ".php"),
		equalFoldExt(ext, ".asp"), equalFoldExt(ext, ".aspx"), equalFoldExt(ext, ".jsp"):
		return true
	case equalFoldExt(ext, ".js"), equalFoldExt(ext, ".css"), equalFoldExt(ext, ".png"),
		equalFoldExt(ext, ".jpg"), equalFoldExt(ext, ".jpeg"), equalFoldExt(ext, ".gif"),
		equalFoldExt(ext, ".webp"), equalFoldExt(ext, ".ico"), equalFoldExt(ext, ".svg"),
		equalFoldExt(ext, ".woff"), equalFoldExt(ext, ".woff2"), equalFoldExt(ext, ".ttf"),
		equalFoldExt(ext, ".map"), equalFoldExt(ext, ".json"), equalFoldExt(ext, ".xml"):
		return false
	default:
		return true
	}
}

func equalFoldExt(ext, want string) bool {
	if len(ext) != len(want) {
		return false
	}
	for i := 0; i < len(ext); i++ {
		ca, cb := ext[i], want[i]
		if ca == cb {
			continue
		}
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func missingSecFetch(r *http.Request) bool {
	return r.Header.Get("Sec-Fetch-Site") == "" &&
		r.Header.Get("Sec-Fetch-Mode") == "" &&
		r.Header.Get("Sec-Fetch-Dest") == ""
}

func secCHUAMismatchBytes(r *http.Request, lowUA []byte) bool {
	ch := r.Header.Get("Sec-CH-UA")
	if ch == "" {
		return false
	}
	bp := lowerPool.Get().(*[]byte)
	lowCH := faststr.AppendLowerASCII((*bp)[:0], ch)
	hit := false
	switch {
	case faststr.ContainsBytes(lowUA, "firefox/") && faststr.ContainsBytes(lowCH, "chrome"):
		hit = true
	case faststr.ContainsBytes(lowUA, "edg/"):
		hit = false
	case faststr.ContainsBytes(lowUA, "chrome/") && !faststr.ContainsBytes(lowUA, "edg/") &&
		faststr.ContainsBytes(lowCH, "firefox"):
		hit = true
	case faststr.ContainsBytes(lowUA, "safari/") && !faststr.ContainsBytes(lowUA, "chrome/") &&
		faststr.ContainsBytes(lowCH, "chrome"):
		hit = true
	}
	*bp = lowCH[:0]
	lowerPool.Put(bp)
	return hit
}

func IsScannerUA(ua string) bool {
	return matchAnyFold(ua, scannerUA) || matchAnyFold(ua, aiUA)
}

func IsAIUA(ua string) bool {
	return matchAnyFold(ua, aiUA)
}
