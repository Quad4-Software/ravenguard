// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ui

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"sync"
)

//go:embed static/*
var staticFS embed.FS

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
}

type Data struct {
	viewBase
	StatusText       string
	RayID            string
	Token            string
	Difficulty       int
	CaptchaEnabled   bool
	PrivacyNoticeURL string
}

type PageData struct {
	viewBase
	RayID  string
	Code   int
	Title  string
	Detail string
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

type Pages struct {
	challenge *template.Template
	page      *template.Template
	testIndex *template.Template
	static    http.Handler
	site      Site
}

var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

func New(site Site) (*Pages, error) {
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
	if site.Robots == "" {
		site.Robots = "noindex, nofollow"
	}
	if site.Lang == "" {
		site.Lang = "en"
	}
	if site.OGImage == "" && site.PublicURL != "" {
		site.OGImage = strings.TrimRight(site.PublicURL, "/") + site.Prefix + "/static/raven.png"
	}

	root, err := template.New("root").ParseFS(staticFS,
		"static/head.html",
		"static/challenge.html",
		"static/page.html",
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
		testIndex: root.Lookup("test.html"),
		static:    http.FileServer(http.FS(sub)),
		site:      site,
	}, nil
}

func (p *Pages) Prefix() string { return p.site.Prefix }

func (p *Pages) Brand() string { return p.site.Brand }

func (p *Pages) base(pageTitle, pathSuffix string) viewBase {
	canonical := ""
	if p.site.PublicURL != "" {
		canonical = strings.TrimRight(p.site.PublicURL, "/") + pathSuffix
	}
	title := pageTitle
	if title == "" {
		title = p.site.Brand
	} else if !strings.Contains(title, p.site.Brand) {
		title = p.site.Brand + " - " + title
	}
	return viewBase{
		Brand:       p.site.Brand,
		Prefix:      p.site.Prefix,
		Lang:        p.site.Lang,
		PageTitle:   title,
		Description: p.site.Description,
		Robots:      p.site.Robots,
		ThemeColor:  p.site.ThemeColor,
		Canonical:   canonical,
		OGImage:     p.site.OGImage,
		PublicURL:   p.site.PublicURL,
	}
}

func (p *Pages) ServeChallenge(w http.ResponseWriter, data Data) {
	data.viewBase = p.base(p.site.StatusText, "/")
	if data.StatusText == "" {
		data.StatusText = p.site.StatusText
	}
	if data.PrivacyNoticeURL == "" {
		data.PrivacyNoticeURL = p.site.PrivacyNoticeURL
	}
	p.render(w, p.challenge, data, http.StatusForbidden, nil)
}

func (p *Pages) RenderBlock(w http.ResponseWriter, ray, reason string) {
	p.RenderPage(w, PageData{
		RayID:  ray,
		Code:   http.StatusForbidden,
		Title:  "Access denied",
		Detail: reason,
	})
}

func (p *Pages) RenderRateLimit(w http.ResponseWriter, ray string) {
	w.Header().Set("Retry-After", "60")
	p.RenderPage(w, PageData{
		RayID:  ray,
		Code:   http.StatusTooManyRequests,
		Title:  "Too many requests",
		Detail: "You have sent too many requests in a short period. Wait a moment and try again.",
	})
}

func (p *Pages) RenderUpstream(w http.ResponseWriter, ray string) {
	p.RenderPage(w, PageData{
		RayID:  ray,
		Code:   http.StatusBadGateway,
		Title:  "Origin unreachable",
		Detail: "RavenGuard could not reach the upstream service. The origin may be offline or misconfigured.",
	})
}

func (p *Pages) RenderError(w http.ResponseWriter, ray, title, detail string, code int) {
	if code < 400 {
		code = http.StatusInternalServerError
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
	if data.Code == 0 {
		data.Code = http.StatusForbidden
	}
	data.viewBase = p.base(data.Title, "/")
	p.render(w, p.page, data, data.Code, nil)
}

func (p *Pages) RenderTestIndex(w http.ResponseWriter, ray string) {
	data := TestIndexData{
		viewBase: p.base("UI preview", p.site.Prefix+"/test"),
		RayID:    ray,
		Links: []TestLink{
			{Href: p.site.Prefix + "/test/challenge", Label: "Challenge", Hint: "JS + PoW interstitial"},
			{Href: p.site.Prefix + "/test/block", Label: "Blocked", Hint: "403 access denied"},
			{Href: p.site.Prefix + "/test/ratelimit", Label: "Rate limit", Hint: "429 too many requests"},
			{Href: p.site.Prefix + "/test/upstream", Label: "Upstream down", Hint: "502 origin unreachable"},
			{Href: p.site.Prefix + "/test/error", Label: "Error", Hint: "500 generic failure"},
		},
	}
	p.render(w, p.testIndex, data, http.StatusOK, nil)
}

func (p *Pages) MountStatic(mux *http.ServeMux) {
	p.MountStaticTo(mux, "")
}

func (p *Pages) MountStaticTo(mux *http.ServeMux, dirRedirect string) {
	prefix := p.site.Prefix + "/static/"
	mux.Handle(prefix, http.StripPrefix(prefix, noDirListing(cacheStatic(p.static), dirRedirect)))
	mux.HandleFunc("/favicon.ico", p.serveEmbeddedFile("favicon.ico", "image/x-icon"))
	mux.HandleFunc("/apple-touch-icon.png", p.serveEmbeddedFile("apple-touch-icon.png", "image/png"))
	mux.HandleFunc("/apple-touch-icon-precomposed.png", p.serveEmbeddedFile("apple-touch-icon.png", "image/png"))
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
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	body := "User-agent: *\nDisallow: /\n"
	if strings.Contains(strings.ToLower(p.site.Robots), "index") && !strings.Contains(strings.ToLower(p.site.Robots), "noindex") {
		body = "User-agent: *\nAllow: /\n"
		if p.site.PublicURL != "" {
			body += "Sitemap: " + strings.TrimRight(p.site.PublicURL, "/") + "/sitemap.xml\n"
		}
	}
	_, _ = w.Write([]byte(body))
}

func (p *Pages) ServeManifest(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	m := map[string]any{
		"name":             p.site.Brand,
		"short_name":       p.site.Brand,
		"description":      p.site.Description,
		"start_url":        "/",
		"display":          "standalone",
		"background_color": p.site.ThemeColor,
		"theme_color":      p.site.ThemeColor,
		"icons": []map[string]string{
			{"src": p.site.Prefix + "/static/favicon-32.png", "sizes": "32x32", "type": "image/png"},
			{"src": p.site.Prefix + "/static/apple-touch-icon.png", "sizes": "180x180", "type": "image/png"},
			{"src": p.site.Prefix + "/static/raven.png", "sizes": "256x256", "type": "image/png"},
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
