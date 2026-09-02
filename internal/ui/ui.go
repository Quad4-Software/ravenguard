// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ui

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"unicode"

	"github.com/Quad4-Software/ravenguard/internal/config"
)

//go:embed static
var staticFS embed.FS

// Site holds live-tunable branding and theme tokens for public pages.
type Site struct {
	Brand            string
	StatusText       string
	Description      string
	PublicURL        string
	OGImage          string
	ThemeColor       string
	Robots           string
	Lang             string
	Prefix           string
	PrivacyNoticeURL string

	LogoURL    string
	FaviconURL string
	Background string
	Foreground string
	Accent     string
	FontSans   string
	FontMono   string

	ChallengeTitle    string
	ChallengeSubtitle string
	BlockTitle        string
	RateLimitTitle    string
	UpstreamTitle     string
	ErrorTitle        string
	FooterText        string
	CustomCSS         template.CSS
	RayLabel          string

	ElementName     string
	BootstrapGlobal string
	WidgetInputName string
	HideBrandMark   bool
	GenericCopy     bool
	ServeManifest   bool
	ServeRootIcons  bool

	WidgetJS     string
	ChallengeJS  string
	ChallengeCSS string
}

type viewBase struct {
	Brand       string
	Prefix      string
	Lang        string
	PageTitle   string
	Description string
	Robots      string
	ThemeColor  string
	Canonical   string
	OGImage     string
	PublicURL   string

	ElementName       string
	BootstrapGlobal   string
	WidgetInputName   string
	ChallengeTitle    string
	ChallengeSubtitle string
	RayLabel          string
	FooterText        string
	LogoURL           string
	HideBrandMark     bool
	ShowBrandMark     bool
	CustomCSS         template.CSS
	Background        string
	Foreground        string
	Accent            string
	FontSans          string
	FontMono          string
	FaviconURL        string
	ServeManifest     bool
	WidgetJS          string
	ChallengeJS       string
	ChallengeCSS      string
	WidgetHTML        template.HTML
}

// Data is the challenge interstitial view model.
type Data struct {
	viewBase
	StatusText       string
	RayID            string
	ChallengeURL     string
	Token            string
	Difficulty       int
	CaptchaEnabled   bool
	PrivacyNoticeURL string
}

// PageData is a status page view model.
type PageData struct {
	viewBase
	RayID  string
	Code   int
	Title  string
	Detail string
}

// AccessData is the password or PIN gate form view model.
type AccessData struct {
	viewBase
	Kind         string
	Action       string
	Label        string
	InputName    string
	Autocomplete string
	InputType    string
}

type TestLink struct {
	Href  string
	Label string
	Hint  string
}

type TestIndexData struct {
	viewBase
	RayID string
	Links []TestLink
}

// Pages serves challenge and status HTML with live site branding.
type Pages struct {
	mu        sync.RWMutex
	challenge *template.Template
	page      *template.Template
	access    *template.Template
	testIndex *template.Template
	static    http.Handler
	site      Site
}

var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// SiteFromConfig maps runtime config into UI site tokens.
func SiteFromConfig(cfg config.Config) Site {
	return Site{
		Brand:             cfg.UI.Brand,
		StatusText:        cfg.UI.StatusText,
		Description:       cfg.Site.Description,
		PublicURL:         cfg.Site.PublicURL,
		OGImage:           cfg.Site.OGImage,
		ThemeColor:        cfg.Site.ThemeColor,
		Robots:            cfg.Site.Robots,
		Lang:              cfg.Site.Lang,
		Prefix:            cfg.Challenge.PathPrefix,
		PrivacyNoticeURL:  cfg.Privacy.PrivacyNoticeURL,
		LogoURL:           cfg.UI.LogoURL,
		FaviconURL:        cfg.UI.FaviconURL,
		Background:        cfg.UI.Background,
		Foreground:        cfg.UI.Foreground,
		Accent:            cfg.UI.Accent,
		FontSans:          cfg.UI.FontSans,
		FontMono:          cfg.UI.FontMono,
		ChallengeTitle:    cfg.UI.ChallengeTitle,
		ChallengeSubtitle: cfg.UI.ChallengeSubtitle,
		BlockTitle:        cfg.UI.BlockTitle,
		RateLimitTitle:    cfg.UI.RateLimitTitle,
		UpstreamTitle:     cfg.UI.UpstreamTitle,
		ErrorTitle:        cfg.UI.ErrorTitle,
		FooterText:        cfg.UI.FooterText,
		CustomCSS:         template.CSS(cfg.UI.CustomCSS), //nolint:gosec // G203: operator CSS from config
		RayLabel:          cfg.UI.RayLabel,
		ElementName:       cfg.Stealth.ElementName,
		BootstrapGlobal:   cfg.Stealth.BootstrapGlobal,
		WidgetInputName:   cfg.Stealth.WidgetInputName,
		HideBrandMark:     cfg.Stealth.HideBrandMark,
		GenericCopy:       cfg.Stealth.GenericCopy,
		ServeManifest:     cfg.Stealth.ServeManifest,
		ServeRootIcons:    cfg.Stealth.ServeRootIcons,
	}
}

func normalizeSite(site Site) Site {
	if site.Prefix == "" {
		site.Prefix = "/_rg"
	}
	site.Prefix = strings.TrimRight(site.Prefix, "/")
	if site.Brand == "" {
		site.Brand = "RavenGuard"
	}
	if site.StatusText == "" {
		site.StatusText = "Checking your browser before accessing this site."
	}
	if site.Description == "" {
		site.Description = site.Brand + " application guard"
	}
	if site.ThemeColor == "" {
		site.ThemeColor = "#050505"
	}
	if site.Background == "" {
		site.Background = site.ThemeColor
	}
	if site.Foreground == "" {
		site.Foreground = "#e8e8e8"
	}
	if site.Accent == "" {
		site.Accent = "#c4c4c4"
	}
	if site.FontSans == "" {
		site.FontSans = `"IBM Plex Sans", "Segoe UI", sans-serif`
	}
	if site.FontMono == "" {
		site.FontMono = `"IBM Plex Mono", "Consolas", monospace`
	}
	if site.Robots == "" {
		site.Robots = "noindex, nofollow"
	}
	if site.Lang == "" {
		site.Lang = "en"
	}
	if site.OGImage == "" && site.PublicURL != "" {
		site.OGImage = strings.TrimRight(site.PublicURL, "/") + site.Prefix + "/static/raven.png"
	}
	if site.ElementName == "" {
		site.ElementName = "rg-check"
	}
	if site.BootstrapGlobal == "" {
		site.BootstrapGlobal = "__g__"
	}
	if site.WidgetInputName == "" {
		site.WidgetInputName = "rg"
	}
	if site.WidgetJS == "" {
		site.WidgetJS = "w.js"
	}
	if site.ChallengeJS == "" {
		site.ChallengeJS = "c.js"
	}
	if site.ChallengeCSS == "" {
		site.ChallengeCSS = "c.css"
	}
	if site.ChallengeSubtitle == "" {
		site.ChallengeSubtitle = "Click the checkbox to verify. Your browser will redirect shortly."
	}
	if site.RayLabel == "" {
		if site.GenericCopy {
			site.RayLabel = "Ref"
		} else {
			site.RayLabel = "Ray ID"
		}
	}
	if site.FooterText == "" {
		site.FooterText = site.Brand
	}
	if site.ChallengeTitle == "" {
		if site.GenericCopy {
			site.ChallengeTitle = "VERIFY"
		} else {
			site.ChallengeTitle = "CHALLENGE"
		}
	}
	return site
}

func New(site Site) (*Pages, error) {
	site = normalizeSite(site)

	root, err := template.New("root").ParseFS(staticFS,
		"static/head.html",
		"static/challenge.html",
		"static/page.html",
		"static/access.html",
		"static/test.html",
	)
	if err != nil {
		return nil, err
	}
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	return &Pages{
		challenge: root.Lookup("challenge.html"),
		page:      root.Lookup("page.html"),
		access:    root.Lookup("access.html"),
		testIndex: root.Lookup("test.html"),
		static:    http.FileServer(http.FS(sub)),
		site:      site,
	}, nil
}

// UpdateSite replaces live branding and theme tokens.
func (p *Pages) UpdateSite(site Site) {
	site = normalizeSite(site)
	p.mu.Lock()
	p.site = site
	p.mu.Unlock()
}

// Site returns a copy of the current site tokens.
func (p *Pages) Site() Site {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.site
}

func (p *Pages) Prefix() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.site.Prefix
}

func (p *Pages) Brand() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.site.Brand
}

func (p *Pages) base(site Site, pageTitle, pathSuffix string) viewBase {
	canonical := ""
	if site.PublicURL != "" {
		canonical = strings.TrimRight(site.PublicURL, "/") + pathSuffix
	}
	title := pageTitle
	if title == "" {
		title = site.Brand
	} else if !strings.Contains(title, site.Brand) {
		title = site.Brand + " - " + title
	}
	logoURL := site.LogoURL
	if logoURL == "" && !site.HideBrandMark {
		logoURL = site.Prefix + "/static/raven.png"
	}
	showMark := logoURL != ""
	return viewBase{
		Brand:             site.Brand,
		Prefix:            site.Prefix,
		Lang:              site.Lang,
		PageTitle:         title,
		Description:       site.Description,
		Robots:            site.Robots,
		ThemeColor:        site.ThemeColor,
		Canonical:         canonical,
		OGImage:           site.OGImage,
		PublicURL:         site.PublicURL,
		ElementName:       site.ElementName,
		BootstrapGlobal:   site.BootstrapGlobal,
		WidgetInputName:   site.WidgetInputName,
		ChallengeTitle:    site.ChallengeTitle,
		ChallengeSubtitle: site.ChallengeSubtitle,
		RayLabel:          site.RayLabel,
		FooterText:        site.FooterText,
		LogoURL:           logoURL,
		HideBrandMark:     site.HideBrandMark,
		ShowBrandMark:     showMark,
		CustomCSS:         site.CustomCSS,
		Background:        site.Background,
		Foreground:        site.Foreground,
		Accent:            site.Accent,
		FontSans:          site.FontSans,
		FontMono:          site.FontMono,
		FaviconURL:        site.FaviconURL,
		ServeManifest:     site.ServeManifest,
		WidgetJS:          site.WidgetJS,
		ChallengeJS:       site.ChallengeJS,
		ChallengeCSS:      site.ChallengeCSS,
	}
}

func sanitizeElementName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return "rg-check"
	}
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" || !strings.Contains(out, "-") {
		return "rg-check"
	}
	if unicode.IsDigit(rune(out[0])) {
		return "rg-check"
	}
	return out
}

func widgetHTML(tag, challengeURL, inputName string) template.HTML {
	tag = sanitizeElementName(tag)
	if inputName == "" {
		inputName = "rg"
	}
	return template.HTML(fmt.Sprintf( //nolint:gosec // G203: tag sanitized by sanitizeElementName
		`<%s id="rg-widget" challenge="%s" name="%s" auto="off" workers="2"></%s>`,
		tag,
		html.EscapeString(challengeURL),
		html.EscapeString(inputName),
		tag,
	))
}

func (p *Pages) ServeChallenge(w http.ResponseWriter, data Data) {
	site := p.Site()
	data.viewBase = p.base(site, site.StatusText, "/")
	if data.StatusText == "" {
		data.StatusText = site.StatusText
	}
	if data.PrivacyNoticeURL == "" {
		data.PrivacyNoticeURL = site.PrivacyNoticeURL
	}
	if data.ChallengeSubtitle == "" {
		data.ChallengeSubtitle = site.ChallengeSubtitle
	}
	if data.ChallengeTitle == "" {
		data.ChallengeTitle = site.ChallengeTitle
	}
	data.WidgetHTML = widgetHTML(site.ElementName, data.ChallengeURL, site.WidgetInputName)
	p.render(w, p.challenge, data, http.StatusForbidden, nil)
}

func (p *Pages) RenderBlock(w http.ResponseWriter, ray, reason string) {
	site := p.Site()
	title := site.BlockTitle
	if title == "" {
		title = "Access denied"
	}
	p.RenderPage(w, PageData{
		RayID:  ray,
		Code:   http.StatusForbidden,
		Title:  title,
		Detail: reason,
	})
}

func (p *Pages) RenderRateLimit(w http.ResponseWriter, ray string) {
	site := p.Site()
	title := site.RateLimitTitle
	if title == "" {
		title = "Too many requests"
	}
	detail := "You have sent too many requests in a short period. Wait a moment and try again."
	w.Header().Set("Retry-After", "60")
	p.RenderPage(w, PageData{
		RayID:  ray,
		Code:   http.StatusTooManyRequests,
		Title:  title,
		Detail: detail,
	})
}

func (p *Pages) RenderUpstream(w http.ResponseWriter, ray string) {
	site := p.Site()
	title := site.UpstreamTitle
	if title == "" {
		title = "Origin unreachable"
	}
	detail := "The origin may be offline or misconfigured."
	if !site.GenericCopy {
		detail = "RavenGuard could not reach the upstream service. The origin may be offline or misconfigured."
	}
	p.RenderPage(w, PageData{
		RayID:  ray,
		Code:   http.StatusBadGateway,
		Title:  title,
		Detail: detail,
	})
}

func (p *Pages) RenderError(w http.ResponseWriter, ray, title, detail string, code int) {
	site := p.Site()
	if code < 400 {
		code = http.StatusInternalServerError
	}
	if title == "" {
		title = site.ErrorTitle
	}
	if title == "" {
		title = "Something went wrong"
	}
	p.RenderPage(w, PageData{
		RayID:  ray,
		Code:   code,
		Title:  title,
		Detail: detail,
	})
}

func (p *Pages) RenderPage(w http.ResponseWriter, data PageData) {
	site := p.Site()
	if data.Code == 0 {
		data.Code = http.StatusForbidden
	}
	data.viewBase = p.base(site, data.Title, "/")
	p.render(w, p.page, data, data.Code, nil)
}

// ServeAccessForm renders the themed password or PIN access gate.
func (p *Pages) ServeAccessForm(w http.ResponseWriter, kind, action string) {
	site := p.Site()
	label := "Password"
	inputName := "password"
	autocomplete := "current-password"
	inputType := "password"
	if strings.EqualFold(kind, "pin") {
		label = "PIN"
		inputName = "pin"
		autocomplete = "one-time-code"
	}
	pageTitle := "Access"
	if site.GenericCopy {
		pageTitle = "Continue"
	}
	data := AccessData{
		viewBase:     p.base(site, pageTitle, "/"),
		Kind:         kind,
		Action:       action,
		Label:        label,
		InputName:    inputName,
		Autocomplete: autocomplete,
		InputType:    inputType,
	}
	p.render(w, p.access, data, http.StatusUnauthorized, nil)
}

func (p *Pages) RenderTestIndex(w http.ResponseWriter, ray string) {
	site := p.Site()
	data := TestIndexData{
		viewBase: p.base(site, "UI preview", site.Prefix+"/test"),
		RayID:    ray,
		Links: []TestLink{
			{Href: site.Prefix + "/test/challenge", Label: "Challenge", Hint: "JS + PoW interstitial"},
			{Href: site.Prefix + "/test/block", Label: "Blocked", Hint: "403 access denied"},
			{Href: site.Prefix + "/test/ratelimit", Label: "Rate limit", Hint: "429 too many requests"},
			{Href: site.Prefix + "/test/upstream", Label: "Upstream down", Hint: "502 origin unreachable"},
			{Href: site.Prefix + "/test/error", Label: "Error", Hint: "500 generic failure"},
		},
	}
	p.render(w, p.testIndex, data, http.StatusOK, nil)
}

func (p *Pages) MountStatic(mux *http.ServeMux) {
	p.MountStaticTo(mux, "")
}

func (p *Pages) MountStaticTo(mux *http.ServeMux, dirRedirect string) {
	site := p.Site()
	prefix := site.Prefix + "/static/"
	mux.Handle(prefix, http.StripPrefix(prefix, noDirListing(cacheStatic(p.static), dirRedirect)))
	if site.ServeRootIcons {
		mux.HandleFunc("/favicon.ico", p.serveEmbeddedFile("favicon.ico", "image/x-icon"))
		mux.HandleFunc("/apple-touch-icon.png", p.serveEmbeddedFile("apple-touch-icon.png", "image/png"))
		mux.HandleFunc("/apple-touch-icon-precomposed.png", p.serveEmbeddedFile("apple-touch-icon.png", "image/png"))
	}
}

func (p *Pages) serveEmbeddedFile(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		b, err := staticFS.ReadFile("static/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(b)
		}
	}
}

func noDirListing(next http.Handler, dirRedirect string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "" || path == "/" || strings.HasSuffix(path, "/") {
			if dirRedirect != "" {
				http.Redirect(w, r, dirRedirect, http.StatusFound)
				return
			}
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (p *Pages) ServeRobots(w http.ResponseWriter, _ *http.Request) {
	site := p.Site()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	body := "User-agent: *\nDisallow: /\n"
	if strings.Contains(strings.ToLower(site.Robots), "index") && !strings.Contains(strings.ToLower(site.Robots), "noindex") {
		body = "User-agent: *\nAllow: /\n"
		if site.PublicURL != "" {
			body += "Sitemap: " + strings.TrimRight(site.PublicURL, "/") + "/sitemap.xml\n"
		}
	}
	_, _ = w.Write([]byte(body))
}

func (p *Pages) ServeManifest(w http.ResponseWriter, _ *http.Request) {
	site := p.Site()
	w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	m := map[string]any{
		"name":             site.Brand,
		"short_name":       site.Brand,
		"description":      site.Description,
		"start_url":        "/",
		"display":          "standalone",
		"background_color": site.ThemeColor,
		"theme_color":      site.ThemeColor,
		"icons": []map[string]string{
			{"src": site.Prefix + "/static/favicon-32.png", "sizes": "32x32", "type": "image/png"},
			{"src": site.Prefix + "/static/apple-touch-icon.png", "sizes": "180x180", "type": "image/png"},
			{"src": site.Prefix + "/static/raven.png", "sizes": "256x256", "type": "image/png"},
		},
	}
	_ = json.NewEncoder(w).Encode(m)
}

func (p *Pages) render(w http.ResponseWriter, tmpl *template.Template, data any, code int, extra http.Header) {
	if tmpl == nil {
		http.Error(w, "template missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	for k, vals := range extra {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	if err := tmpl.Execute(buf, data); err != nil {
		bufPool.Put(buf)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
	buf.Reset()
	bufPool.Put(buf)
}

func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		next.ServeHTTP(w, r)
	})
}
