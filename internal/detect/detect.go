// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect

import (
	"net/http"
	"strconv"
	"strings"
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
	EmptyFormContextScore  int
	ForumWritePathScore    int
	ForgeExpensiveScore    int
	ProxyBotLowScore       int
	ProxyBotHeader         string
	ProxyBotScoreHeader    string
	ProxyJA4Header         string
	// MissingAcceptEncScore applies to browser-like UAs that omit
	// Accept-Encoding. Every real browser sends it on every request.
	MissingAcceptEncScore int
	// SecCHUANonChromiumScore applies when a Firefox or Safari UA still
	// sends Chromium client hints. Those browsers never emit Sec-CH-UA.
	SecCHUANonChromiumScore int
	// HTTP10BrowserScore applies to browser-like UAs arriving on HTTP/1.0,
	// which modern browsers never use.
	HTTP10BrowserScore int
	// MissingContentTypeScore applies to browser-like UAs sending a body
	// without Content-Type. Browsers always declare one on writes.
	MissingContentTypeScore int
	// LongUAScore applies to absurdly long User-Agent strings or strings
	// containing control bytes, a hallmark of bot tooling.
	LongUAScore int
	// MissingUIRScore applies to Chrome or Firefox UAs fetching a document
	// without Upgrade-Insecure-Requests, which both always send.
	MissingUIRScore int
	// SNIHostMismatchScore applies when the TLS SNI and Host header disagree,
	// a sign of domain fronting or off-target scanning. Only meaningful when
	// RavenGuard terminates TLS; leave unset behind a TLS-terminating proxy.
	SNIHostMismatchScore int
}

type Result struct {
	Score   int
	Reasons []string
}

// scannerUA matches vulnerability scanners, HTTP libraries, SEO crawlers,
// headless clients, forum spam tools, and browser-automation agents.
var scannerUA = []string{
	"sqlmap", "nikto", "nmap", "masscan", "zgrab", "zgrab2",
	"dirbuster", "gobuster", "wfuzz", "ffuf", "nuclei", "httpx",
	"acunetix", "nessus", "openvas", "w3af", "burpsuite", "burp/",
	"python-requests", "python-urllib", "aiohttp",
	"go-http-client", "scrapy", "curl/", "wget/", "libwww-perl",
	"libcurl", "java/", "okhttp", "apache-httpclient", "axios/",
	"node-fetch", "undici", "postmanruntime", "insomnia/",
	"phantomjs", "headlesschrome", "puppeteer",
	"playwright", "selenium", "chromedriver", "geckodriver",
	"crawl4ai", "firecrawl", "browser-use", "scrapling",
	"httrack", "semrush", "ahrefs", "mj12bot", "dotbot",
	"petalbot", "dataforseobot", "serpstat", "majestic", "rogerbot",
	"screaming frog", "seokicks", "blexbot", "linkdexbot",
	"xrumer", "scrapebox", "gsa ser", "senukai", "magic submitter",
	"sape_api", "botasaurus", "nodriver", "zendriver", "camoufox",
	"seleniumbase", "undetected_chromedriver", "uc_chrome",
	"rebrowser", "browserless", "steel-browser", "skyvern",
	"langchain", "crewai", "autogen/", "openai-agents",
}

// aiUA matches documented AI training crawlers, answer-engine indexers,
// and user-triggered AI fetch or agent clients (research snapshot 2026).
var aiUA = []string{
	"gptbot", "chatgpt-user", "oai-searchbot", "chatgpt-atlas",
	"claudebot", "claude-user", "claude-searchbot", "claude-web",
	"claude-code", "anthropic-ai", "anthropic/",
	"bytespider", "ccbot", "google-extended", "google-agent",
	"google-cloudvertexbot", "googleagent-mariner", "googleother",
	"meta-externalagent", "meta-externalfetcher", "facebookbot",
	"facebookexternalhit",
	"perplexitybot", "perplexity-user",
	"amazonbot", "cohere-ai", "ai2bot", "diffbot", "youbot",
	"omgili", "omgilibot", "webzio", "imagesiftbot",
	"applebot-extended", "mistralai-user", "duckassistbot",
	"timpibot", "pangubot", "kangaroo bot", "kangaroobot",
	"deepseekbot", "qwenbot", "iaskspider", "phindbot",
	"notebooklm", "gemini-deep-research",
}

// forumWritePaths are path segments commonly abused by registration and comment spam bots.
// Matched as whole segments so /api/contacting and /private-key do not hit.
var forumWritePaths = []string{
	"comment", "comments", "reply", "replies",
	"newthread", "newtopic", "new-topic", "posting",
	"register", "signup", "sign-up", "create-account",
	"guestbook", "wp-comments-post",
}

var probePaths = []string{
	"/.env", "/wp-admin", "/wp-login", "/xmlrpc.php", "/phpmyadmin",
	"/.git", "/admin", "/actuator", "/server-status", "/cgi-bin",
	"/vendor/phpunit", "/etc/passwd", "/.aws", "/api/v1/admin",
	"/console", "/manager/html", "/owa/", "/hnap1",
	// Version-control and IDE leftovers leaked by deployments.
	"/.svn", "/.hg", "/.bzr", "/.ds_store", "/.vscode", "/.idea",
	"/.npmrc", "/.ssh", "/composer.json", "/vendor/composer",
	// App-specific recon endpoints seen in scanner template sets.
	// /wp-content and /wp-includes are deliberately excluded: they are the
	// normal asset paths on every WordPress site.
	"/server-info", "/phpinfo", "/boaform", "/hudson", "/jmx-console",
	"/elmah", "/debug/vars", "/debug/pprof", "/wp-login", "/xmlrpc.php",
	"/host-manager", "/druid", "/nacos", "/geoserver",
	"/actuator/env", "/actuator/heapdump", "/actuator/beans",
	// Backup dumps and webshell names probed by exploit bots.
	"/db.sql", "/dump.sql", "/backup.sql", "/backup.zip", "/backup.tar",
	"/wp-config", "/shell.php", "/cmd.php", "/up.php", "/c99", "/r57",
	"/webshell",
}

var lowerPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 256)
		return &b
	},
}

var (
	scannerMatcher = faststr.NewMatcher(scannerUA)
	aiMatcher      = faststr.NewMatcher(aiUA)
)

func Score(r *http.Request, cfg Config) Result {
	return score(r, cfg, false)
}

// ScoreDebug is Score with reason strings for diagnostics and tests.
func ScoreDebug(r *http.Request, cfg Config) Result {
	return score(r, cfg, true)
}

// IsGitSmartHTTP reports whether r is a Git smart-HTTP negotiation or
// pack transfer request. Git clients cannot render a browser challenge,
// so these requests are excluded from detect scoring and challenge gating.
func IsGitSmartHTTP(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	ua := r.Header.Get("User-Agent")
	if !faststr.HasPrefixFold(ua, "git/") {
		return false
	}
	path := r.URL.Path
	if strings.HasSuffix(path, "/git-upload-pack") ||
		strings.HasSuffix(path, "/git-receive-pack") {
		return true
	}
	if strings.HasSuffix(path, "/info/refs") {
		svc, ok := rawQueryValue(r.URL.RawQuery, "service")
		return ok && (strings.EqualFold(svc, "git-upload-pack") || strings.EqualFold(svc, "git-receive-pack"))
	}
	return false
}

// rawQueryValue returns the first value for key in a raw URL query string
// without allocating. It does not unescape the value.
func rawQueryValue(raw, key string) (string, bool) {
	prefix := key + "="
	n := len(prefix)
	for raw != "" {
		i := strings.Index(raw, prefix)
		if i < 0 {
			return "", false
		}
		if i > 0 && raw[i-1] != '&' {
			// not at a key boundary, keep searching
			raw = raw[i+n:]
			continue
		}
		j := i + n
		for j < len(raw) && raw[j] != '&' {
			j++
		}
		return raw[i+n : j], true
	}
	return "", false
}

func score(r *http.Request, cfg Config, wantReasons bool) Result {
	var res Result
	if IsGitSmartHTTP(r) {
		return res
	}
	ua := r.Header.Get("User-Agent")

	// Spoofing the Git UA on non-smart-HTTP paths is a common bypass attempt.
	if faststr.HasPrefixFold(ua, "git/") {
		res.Score += cfg.ScannerUAScore
		if wantReasons {
			res.Reasons = append(res.Reasons, "git ua on non-smart path")
		}
	}

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
		if scannerMatcher.Contains(lowUA) {
			res.Score += cfg.ScannerUAScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "scanner_ua")
			}
		}
		if aiMatcher.Contains(lowUA) {
			score := cfg.AIUAScore
			if score <= 0 {
				score = cfg.ScannerUAScore
			}
			res.Score += score
			if wantReasons {
				res.Reasons = append(res.Reasons, "ai_ua")
			}
		}
		if uaAnomalous(ua) && cfg.LongUAScore > 0 {
			res.Score += cfg.LongUAScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "ua_anomalous")
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
		if r.Header.Get("Accept-Encoding") == "" && cfg.MissingAcceptEncScore > 0 {
			res.Score += cfg.MissingAcceptEncScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "missing_accept_encoding")
			}
		}
		if isDocumentGET(r) && missingSecFetch(r) && cfg.MissingSecFetchScore > 0 {
			res.Score += cfg.MissingSecFetchScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "missing_sec_fetch")
			}
		}
		chMismatch := secCHUAMismatchBytes(r, lowUA)
		if chMismatch && cfg.SecCHUAMismatchScore > 0 {
			res.Score += cfg.SecCHUAMismatchScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "sec_ch_ua_mismatch")
			}
		}
		if !chMismatch && secCHUAOnNonChromiumBytes(r, lowUA) && cfg.SecCHUANonChromiumScore > 0 {
			res.Score += cfg.SecCHUANonChromiumScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "sec_ch_ua_non_chromium")
			}
		}
		if r.ProtoMajor == 1 && r.ProtoMinor == 0 && cfg.HTTP10BrowserScore > 0 {
			res.Score += cfg.HTTP10BrowserScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "http10_browser")
			}
		}
		if chromiumOrFirefoxUA(lowUA) && isDocumentGET(r) &&
			r.Header.Get("Upgrade-Insecure-Requests") == "" && cfg.MissingUIRScore > 0 {
			res.Score += cfg.MissingUIRScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "missing_upgrade_insecure")
			}
		}
		if missingContentTypeOnWrite(r) && cfg.MissingContentTypeScore > 0 {
			res.Score += cfg.MissingContentTypeScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "missing_content_type")
			}
		}
		if accept == "*/*" && isDocumentPath(r.URL.Path) && cfg.StarAcceptBrowserScore > 0 {
			res.Score += cfg.StarAcceptBrowserScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "star_accept_browser")
			}
		}
		scoreFormSpam(r, cfg, &res, wantReasons)
	}

	if cfg.SNIHostMismatchScore > 0 && sniHostMismatch(r) {
		res.Score += cfg.SNIHostMismatchScore
		if wantReasons {
			res.Reasons = append(res.Reasons, "sni_host_mismatch")
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
	if cfg.ForgeExpensiveScore > 0 && ForgePathClass(path) == ForgeHot {
		res.Score += cfg.ForgeExpensiveScore
		if wantReasons {
			res.Reasons = append(res.Reasons, "forge_expensive")
		}
	}

	if lowUAPtr != nil {
		*lowUAPtr = lowUA[:0]
		lowerPool.Put(lowUAPtr)
	}

	scoreProxySignals(r, cfg, &res, wantReasons)
	return res
}

func scoreFormSpam(r *http.Request, cfg Config, res *Result, wantReasons bool) {
	if !isWriteMethod(r.Method) {
		return
	}
	emptyCtx := r.Header.Get("Origin") == "" && r.Header.Get("Referer") == ""
	formLike := isBrowserFormContentType(r.Header.Get("Content-Type"))
	forumPath := forumWritePath(r.URL.Path)

	// Empty Origin+Referer is only scored for form posts or known spam write paths.
	// Plain JSON/API writes from browser-like UAs are common on general sites.
	if emptyCtx && cfg.EmptyFormContextScore > 0 && (formLike || forumPath) {
		res.Score += cfg.EmptyFormContextScore
		if wantReasons {
			res.Reasons = append(res.Reasons, "empty_form_context")
		}
	}
	if forumPath && cfg.ForumWritePathScore > 0 {
		suspicious := emptyCtx || missingSecFetch(r)
		if suspicious {
			res.Score += cfg.ForumWritePathScore
			if wantReasons {
				res.Reasons = append(res.Reasons, "forum_write_path")
			}
		}
	}
}

func isBrowserFormContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return false
	}
	return strings.HasPrefix(ct, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(ct, "multipart/form-data")
}

func isWriteMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func forumWritePath(path string) bool {
	if path == "" {
		return false
	}
	start := 0
	for i := 0; i <= len(path); i++ {
		if i < len(path) && path[i] != '/' {
			continue
		}
		if i > start {
			seg := path[start:i]
			for _, p := range forumWritePaths {
				if len(seg) == len(p) && strings.EqualFold(seg, p) {
					return true
				}
			}
		}
		start = i + 1
	}
	return false
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

func matchAnyFold(s string, m *faststr.Matcher) bool {
	if s == "" || m == nil {
		return false
	}
	bp := lowerPool.Get().(*[]byte)
	low := faststr.AppendLowerASCII((*bp)[:0], s)
	ok := m.Contains(low)
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

// uaAnomalous reports whether ua is implausibly long or contains control
// bytes. Real browsers cap around 200 chars and never emit controls.
func uaAnomalous(ua string) bool {
	if len(ua) > 280 {
		return true
	}
	for i := 0; i < len(ua); i++ {
		if ua[i] < 0x20 && ua[i] != '\t' {
			return true
		}
	}
	return false
}

// chromiumOrFirefoxUA reports whether the UA claims Chrome, Edge, or
// Firefox. Those browsers always send Upgrade-Insecure-Requests.
func chromiumOrFirefoxUA(low []byte) bool {
	return faststr.ContainsBytes(low, "chrome/") ||
		faststr.ContainsBytes(low, "edg/") ||
		faststr.ContainsBytes(low, "firefox/")
}

// secCHUAOnNonChromiumBytes reports whether the request sends Chromium
// client hints while the UA claims a browser that never emits them.
// Safari and Firefox do not send Sec-CH-UA at all.
func secCHUAOnNonChromiumBytes(r *http.Request, lowUA []byte) bool {
	if r.Header.Get("Sec-CH-UA") == "" {
		return false
	}
	chromium := faststr.ContainsBytes(lowUA, "chrome/") ||
		faststr.ContainsBytes(lowUA, "chromium") ||
		faststr.ContainsBytes(lowUA, "edg/") ||
		faststr.ContainsBytes(lowUA, "opr/")
	return !chromium
}

// missingContentTypeOnWrite reports whether a write request carries a body
// but no Content-Type. Browsers always declare one.
func missingContentTypeOnWrite(r *http.Request) bool {
	if !isWriteMethod(r.Method) {
		return false
	}
	hasBody := r.ContentLength != 0 || (r.Body != nil && r.Body != http.NoBody)
	return hasBody && r.Header.Get("Content-Type") == ""
}

// sniHostMismatch reports whether the TLS SNI and the HTTP Host header name
// different sites. Browsers send the same name for both; disagreement is a
// sign of domain fronting or scanners reusing a TLS session.
func sniHostMismatch(r *http.Request) bool {
	if r.TLS == nil || r.TLS.ServerName == "" {
		return false
	}
	host := r.Host
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimSuffix(host, ".")
	sni := strings.TrimSuffix(r.TLS.ServerName, ".")
	if host == "" {
		return false
	}
	return !strings.EqualFold(host, sni)
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
	return matchAnyFold(ua, scannerMatcher) || matchAnyFold(ua, aiMatcher)
}

func IsAIUA(ua string) bool {
	return matchAnyFold(ua, aiMatcher)
}

// IsSSE reports whether r is an EventSource (text/event-stream) request.
func IsSSE(r *http.Request) bool {
	if r == nil {
		return false
	}
	// faststr.ContainsFold is ASCII case-insensitive and zero-alloc.
	return faststr.ContainsFold(r.Header.Get("Accept"), "text/event-stream")
}

// IsWebSocketUpgrade reports whether r is a WebSocket handshake.
func IsWebSocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	return headerHasTokenFold(r.Header.Get("Connection"), "upgrade")
}

// headerHasTokenFold reports whether a comma-separated header value contains
// token using ASCII case folding. It scans the string without allocating.
// token must be lowercase ASCII.
func headerHasTokenFold(s, token string) bool {
	tn := len(token)
	if tn == 0 {
		return true
	}
	n := len(s)
	i := 0
	for i < n {
		// skip leading spaces and commas
		for i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == ',') {
			i++
		}
		start := i
		for i < n && s[i] != ',' {
			i++
		}
		end := i
		// trim trailing spaces
		for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
			end--
		}
		if end-start == tn {
			match := true
			for j := range tn {
				c := s[start+j]
				want := token[j]
				if c == want {
					continue
				}
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				if c != want {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
		if i < n && s[i] == ',' {
			i++
		}
	}
	return false
}

// IsWebTransport reports whether r is a WebTransport session request.
// It matches HTTP/3 CONNECT with the webtransport protocol or the HTTP/2
// Upgrade fallback and version negotiation header.
func IsWebTransport(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.Method == http.MethodConnect && r.ProtoMajor >= 3 {
		return true
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "webtransport") {
		return true
	}
	if r.Header.Get("Sec-WebTransport-Version") != "" {
		return true
	}
	return false
}

// IsStreamProtocol reports whether r uses a protocol that cannot render
// a JavaScript challenge (SSE, WebSocket, or WebTransport).
func IsStreamProtocol(r *http.Request) bool {
	return IsSSE(r) || IsWebSocketUpgrade(r) || IsWebTransport(r)
}
