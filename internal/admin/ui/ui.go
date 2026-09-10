// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ui

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"
)

//go:embed assets/* assets/css/* assets/fonts/* assets/js/* templates/* templates/pages/*
var embedFS embed.FS

// UI renders the admin console with HTMX and server-side Go templates.
type UI struct {
	apiMux   http.Handler
	basePath string
	tmpl     *template.Template
	static   http.Handler
}

// New creates an admin UI that dispatches JSON API calls through apiMux.
func New(apiMux http.Handler, basePath string) (*UI, error) {
	basePath = strings.TrimSuffix(basePath, "/")

	staticSub, err := fs.Sub(embedFS, "assets")
	if err != nil {
		return nil, err
	}

	u := &UI{
		apiMux:   apiMux,
		basePath: basePath,
		static:   http.StripPrefix(basePath+"/assets/", http.FileServer(http.FS(staticSub))),
	}

	funcs := template.FuncMap{
		"json":            json.Marshal,
		"baseURL":         func() string { return basePath },
		"formatBytes":     formatBytes,
		"formatPct":       formatPct,
		"formatNum":       formatNum,
		"formatUptime":    formatUptime,
		"formatNs":        formatNs,
		"formatTime":      formatTime,
		"max":             maxAny,
		"add":             func(a, b float64) float64 { return a + b },
		"sub":             func(a, b float64) float64 { return a - b },
		"mul":             func(a, b float64) float64 { return a * b },
		"div":             func(a, b float64) float64 { return a / b },
		"gt":              gtAny,
		"list":            func(v ...any) []any { return v },
		"dict":            dict,
		"roleRank":        roleRank,
		"roleAtLeast":     roleAtLeast,
		"canWriteOps":     canWriteOps,
		"canWriteCfg":     canWriteConfig,
		"canManageUsers":  canManageUsers,
		"canManageOwners": canManageOwners,
		"navActive":       navActive,
		"navHref":         navHref,
		"navLinks":        navLinks,
		"navVisible":      navVisible,
		"sparklineSVG":    sparklineSVG,
		"gaugeSVG":        gaugeSVG,
		"barMeter":        barMeter,
		"sampleSeries":    sampleSeries,
		"sampleLast":      sampleLast,
		"statusTone":      statusTone,
		"moduleState":     moduleState,
		"hasPrefix":       strings.HasPrefix,
		"include":         u.include,
	}

	tmpl, err := template.New("admin").Funcs(funcs).ParseFS(embedFS,
		"templates/*.html",
		"templates/pages/*.html",
	)
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	u.tmpl = tmpl
	return u, nil
}

// Mount registers admin UI routes on mux. The API mux must already be mounted.
func (u *UI) Mount(mux *http.ServeMux) {
	base := strings.TrimSuffix(u.basePath, "/")
	mux.Handle(base+"/assets/", u.static)
	mux.HandleFunc(base+"/", u.route)
}

func (u *UI) route(w http.ResponseWriter, r *http.Request) {
	p := u.trimBase(r.URL.Path)

	switch {
	case p == "/login":
		u.handleLogin(w, r)
	case p == "/logout":
		u.handleLogout(w, r)
	case p == "/" || p == "":
		u.handleOverview(w, r)
	case p == "/settings":
		u.handleSettings(w, r)
	case p == "/bans":
		u.handleBans(w, r)
	case p == "/blocklists":
		u.handleBlocklists(w, r)
	case p == "/config":
		u.handleConfig(w, r)
	case p == "/tokens":
		u.handleTokens(w, r)
	case p == "/audit":
		u.handleAudit(w, r)
	case p == "/qfeeds":
		u.handleQFeeds(w, r)
	case p == "/appearance":
		u.handleAppearance(w, r)
	case p == "/threatintel":
		u.handleThreatIntel(w, r)
	case strings.HasPrefix(p, "/upstreams"):
		u.handleUpstreams(w, r)
	case strings.HasPrefix(p, "/routes"):
		u.handleRoutes(w, r)
	case strings.HasPrefix(p, "/access"):
		u.handleAccess(w, r)
	case strings.HasPrefix(p, "/schemas"):
		u.handleSchemas(w, r)
	case strings.HasPrefix(p, "/certs"):
		u.handleCerts(w, r)
	case p == "/logs":
		u.handleLogs(w, r)
	case strings.HasPrefix(p, "/requests"):
		u.handleRequests(w, r)
	case strings.HasPrefix(p, "/proxies"):
		u.handleProxies(w, r)
	case strings.HasPrefix(p, "/migrations"):
		u.handleMigrations(w, r)
	case p == "/users":
		u.handleUsers(w, r)
	default:
		u.handlePage(w, r, p)
	}
}

func (u *UI) trimBase(p string) string {
	base := u.basePath
	if base != "" && base != "/" {
		p = strings.TrimPrefix(p, base)
	}
	if p == "" {
		p = "/"
	}
	return p
}

// PageData is the common view model passed to every page.
type PageData struct {
	BasePath     string
	User         *User
	Role         string
	CSRF         string
	PageTitle    string
	PagePath     string
	TemplateName string
	Error        string
	Data         any
}

// User mirrors the public fields returned by /auth/me.
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Disabled bool   `json:"disabled"`
}

func (u *UI) requireAuth(r *http.Request) (*User, string, bool) {
	status, body, _, err := u.apiGET(r, "/auth/me")
	if err != nil || status != http.StatusOK {
		return nil, "", false
	}
	var session struct {
		User      User   `json:"user"`
		CSRFToken string `json:"csrf_token"`
		TokenAuth bool   `json:"token_auth"`
	}
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, "", false
	}
	return &session.User, session.CSRFToken, true
}

func (u *UI) redirect(w http.ResponseWriter, r *http.Request, target string) {
	http.Redirect(w, r, u.basePath+target, http.StatusFound)
}

func (u *UI) render(w http.ResponseWriter, r *http.Request, name string, data PageData) {
	data.BasePath = u.basePath
	data.PagePath = u.trimBase(r.URL.Path)
	if data.TemplateName == "" {
		data.TemplateName = name
	}

	if r.Header.Get("HX-Request") == "true" {
		if t := u.tmpl.Lookup(name + "-fragment"); t != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_ = t.Execute(w, data)
			return
		}
	}

	if t := u.tmpl.Lookup(name); t == nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = u.tmpl.ExecuteTemplate(w, name, data)
}

func (u *UI) renderError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Retarget", "#toast-stack")
		w.Header().Set("HX-Reswap", "beforeend")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(toastHTML("error", msg)))
		return
	}
	u.render(w, r, "error", PageData{Error: msg})
}

func (u *UI) handlePage(w http.ResponseWriter, r *http.Request, p string) {
	user, csrf, ok := u.requireAuth(r)
	if !ok {
		u.redirect(w, r, "/login")
		return
	}
	u.render(w, r, "page", PageData{User: user, CSRF: csrf, PageTitle: "RavenGuard", Data: map[string]any{"path": p}})
}

func (u *UI) apiGET(r *http.Request, apiPath string) (int, []byte, http.Header, error) {
	return u.apiCall(r, http.MethodGet, apiPath, nil, "")
}

func (u *UI) apiPOST(r *http.Request, apiPath string, body any) (int, []byte, http.Header, error) {
	return u.apiCall(r, http.MethodPost, apiPath, body, "application/json")
}

func (u *UI) apiPUT(r *http.Request, apiPath string, body any) (int, []byte, http.Header, error) {
	return u.apiCall(r, http.MethodPut, apiPath, body, "application/json")
}

func (u *UI) apiPATCH(r *http.Request, apiPath string, body any) (int, []byte, http.Header, error) {
	return u.apiCall(r, http.MethodPatch, apiPath, body, "application/json")
}

func (u *UI) apiDELETE(r *http.Request, apiPath string) (int, []byte, http.Header, error) {
	return u.apiCall(r, http.MethodDelete, apiPath, nil, "")
}

func (u *UI) apiCall(r *http.Request, method, apiPath string, body any, contentType string) (int, []byte, http.Header, error) {
	target := u.basePath + "/api/v1" + apiPath
	if !strings.HasPrefix(target, "/") {
		target = "/" + target
	}

	var bodyReader io.Reader
	var bodyLen int64
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, nil, err
		}
		bodyReader = bytes.NewReader(b)
		bodyLen = int64(len(b))
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	inner := r.Clone(ctx)
	inner.Method = method
	inner.URL = &url.URL{Path: target, RawQuery: r.URL.RawQuery}
	inner.RequestURI = target
	inner.Body = io.NopCloser(bodyReader)
	inner.ContentLength = bodyLen
	inner.Header = r.Header.Clone()
	if contentType != "" {
		inner.Header.Set("Content-Type", contentType)
	}

	rr := httptest.NewRecorder()
	u.apiMux.ServeHTTP(rr, inner)

	res := rr.Result()
	b, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		return 0, nil, nil, err
	}
	return res.StatusCode, b, res.Header, nil
}

func forwardCookies(w http.ResponseWriter, hdr http.Header) {
	for _, c := range hdr.Values("Set-Cookie") {
		w.Header().Add("Set-Cookie", c)
	}
}

func parseAPIError(body []byte) string {
	var m struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &m); err == nil && m.Error != "" {
		return m.Error
	}
	return "request failed"
}

func (u *UI) include(name string, data any) template.HTML {
	var buf bytes.Buffer
	if t := u.tmpl.Lookup(name); t == nil {
		return template.HTML("")
	}
	if err := u.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		return template.HTML("<p class=\"alert alert-error\">template " + name + ": " + err.Error() + "</p>")
	}
	return template.HTML(buf.Bytes())
}

func (u *UI) formJSON(r *http.Request) (map[string]any, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	out := make(map[string]any, len(r.PostForm))
	for k, v := range r.PostForm {
		if len(v) == 1 {
			out[k] = v[0]
		} else {
			out[k] = v
		}
	}
	return out, nil
}

func (u *UI) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
