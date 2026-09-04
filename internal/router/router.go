// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package router

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/health"
	"github.com/Quad4-Software/ravenguard/internal/proxy"
)

// Upstream is a named backend target.
type Upstream struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	URL                 string   `json:"url"`
	ConnectTimeout      string   `json:"connect_timeout,omitempty"`
	ResponseHeader      string   `json:"response_header_timeout,omitempty"`
	IdleConnTimeout     string   `json:"idle_conn_timeout,omitempty"`
	MaxIdleConns        int      `json:"max_idle_conns,omitempty"`
	MaxIdleConnsPerHost int      `json:"max_idle_conns_per_host,omitempty"`
	MaxConnsPerHost     int      `json:"max_conns_per_host,omitempty"`
	FlushInterval       string   `json:"flush_interval,omitempty"`
	SetHeaders          []string `json:"set_headers,omitempty"`
	HealthEnabled       bool     `json:"health_enabled"`
	HealthPath          string   `json:"health_path,omitempty"`
	HealthInterval      string   `json:"health_interval,omitempty"`
	HealthTimeout       string   `json:"health_timeout,omitempty"`
}

// Route maps host + path prefix to an upstream.
type Route struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Enabled        bool     `json:"enabled"`
	Hosts          []string `json:"hosts"`
	PathPrefix     string   `json:"path_prefix"`
	UpstreamID     string   `json:"upstream_id"`
	StripPrefix    bool     `json:"strip_prefix"`
	Priority       int      `json:"priority"`
	AccessPolicyID  string   `json:"access_policy_id,omitempty"`
	OpenAPISchemaID string   `json:"openapi_schema_id,omitempty"`
}

// Match holds the resolved route for a request.
type Match struct {
	Route    Route
	Upstream Upstream
}

type compiled struct {
	route    Route
	hosts    map[string]struct{}
	prefix   string
	upstream Upstream
	proxy    http.Handler
	health   *health.Checker
}

// Table is a thread-safe host+path router with per-upstream proxies.
type Table struct {
	mu             sync.RWMutex
	compiled       []compiled
	byID           map[string]compiled
	fallback       http.Handler
	fallbackHealth *health.Checker
	errHandler     func(http.ResponseWriter, *http.Request, error)
	ctx            context.Context
	cancel         context.CancelFunc
}

// New returns an empty table. Call Replace or SetFallback before serving.
func New(parent context.Context) *Table {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &Table{
		byID:   make(map[string]compiled),
		ctx:    ctx,
		cancel: cancel,
	}
}

// SetErrorHandler sets the upstream error renderer.
func (t *Table) SetErrorHandler(fn func(http.ResponseWriter, *http.Request, error)) {
	t.mu.Lock()
	t.errHandler = fn
	t.mu.Unlock()
}

// SetFallback installs a single reverse proxy used when no routes are configured.
func (t *Table) SetFallback(p http.Handler, hc *health.Checker) {
	t.mu.Lock()
	t.fallback = p
	t.fallbackHealth = hc
	t.mu.Unlock()
}

// Close stops health checkers owned by the table.
func (t *Table) Close() {
	t.cancel()
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range t.compiled {
		if c.health != nil {
			c.health.Stop()
		}
	}
	if t.fallbackHealth != nil {
		t.fallbackHealth.Stop()
	}
}

// Replace rebuilds the route table from upstream and route definitions.
func (t *Table) Replace(upstreams []Upstream, routes []Route) error {
	upByID := make(map[string]Upstream, len(upstreams))
	for _, u := range upstreams {
		upByID[u.ID] = u
	}

	type scored struct {
		c        compiled
		priority int
		preflen  int
	}
	var scoredList []scored
	for _, rt := range routes {
		if !rt.Enabled {
			continue
		}
		up, ok := upByID[rt.UpstreamID]
		if !ok {
			continue
		}
		prefix := rt.PathPrefix
		if prefix == "" {
			prefix = "/"
		}
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		p, hc, err := t.buildProxy(up, rt.StripPrefix, prefix)
		if err != nil {
			return err
		}
		hosts := make(map[string]struct{}, len(rt.Hosts))
		for _, h := range rt.Hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				continue
			}
			hosts[h] = struct{}{}
		}
		scoredList = append(scoredList, scored{
			c: compiled{
				route:    rt,
				hosts:    hosts,
				prefix:   prefix,
				upstream: up,
				proxy:    p,
				health:   hc,
			},
			priority: rt.Priority,
			preflen:  len(prefix),
		})
	}

	for i := 0; i < len(scoredList); i++ {
		for j := i + 1; j < len(scoredList); j++ {
			swap := false
			if scoredList[i].priority < scoredList[j].priority {
				swap = true
			} else if scoredList[i].priority == scoredList[j].priority && scoredList[i].preflen < scoredList[j].preflen {
				swap = true
			}
			if swap {
				scoredList[i], scoredList[j] = scoredList[j], scoredList[i]
			}
		}
	}

	built := make([]compiled, len(scoredList))
	byID := make(map[string]compiled, len(scoredList))
	for i, s := range scoredList {
		built[i] = s.c
		byID[s.c.route.ID] = s.c
	}

	t.mu.Lock()
	old := t.compiled
	t.compiled = built
	t.byID = byID
	t.mu.Unlock()

	for _, c := range old {
		if c.health != nil {
			c.health.Stop()
		}
	}
	return nil
}

func (t *Table) buildProxy(up Upstream, strip bool, prefix string) (http.Handler, *health.Checker, error) {
	target, err := proxy.ParseUpstreamURL(up.URL)
	if err != nil {
		return nil, nil, err
	}
	t.mu.RLock()
	errHandler := t.errHandler
	t.mu.RUnlock()

	cfg := proxy.Config{
		Target:                target,
		ConnectTimeout:        parseDur(up.ConnectTimeout, 5*time.Second),
		ResponseHeaderTimeout: parseDur(up.ResponseHeader, 30*time.Second),
		IdleConnTimeout:       parseDur(up.IdleConnTimeout, 90*time.Second),
		MaxIdleConns:          up.MaxIdleConns,
		MaxIdleConnsPerHost:   up.MaxIdleConnsPerHost,
		MaxConnsPerHost:       up.MaxConnsPerHost,
		FlushInterval:         parseDur(up.FlushInterval, -1),
		SetHeaders:            proxy.ParseSetHeaders(up.SetHeaders),
		ErrorHandler:          errHandler,
	}
	if strip && prefix != "" && prefix != "/" {
		cfg.StripPrefix = strings.TrimSuffix(prefix, "/")
	}
	rp := proxy.New(cfg)

	var hc *health.Checker
	if up.HealthEnabled {
		hc = health.New(health.Config{
			Enabled:  true,
			URL:      target,
			Path:     up.HealthPath,
			Interval: parseDur(up.HealthInterval, 10*time.Second),
			Timeout:  parseDur(up.HealthTimeout, 3*time.Second),
			Dial:     proxy.DialFunc(target, cfg.ConnectTimeout),
		})
		hc.Start(t.ctx)
	}
	return rp, hc, nil
}

// Lookup finds the best matching route for the request.
func (t *Table) Lookup(r *http.Request) (Match, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	c, ok := t.matchLocked(r)
	if !ok {
		return Match{}, false
	}
	return Match{Route: c.route, Upstream: c.upstream}, true
}

func (t *Table) matchLocked(r *http.Request) (compiled, bool) {
	host := stripPort(r.Host)
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	for _, c := range t.compiled {
		if len(c.hosts) > 0 {
			if _, ok := c.hosts[host]; !ok {
				continue
			}
		}
		if matchPrefix(path, c.prefix) {
			return c, true
		}
	}
	return compiled{}, false
}

// ServeHTTP proxies to the matched upstream or fallback.
func (t *Table) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.mu.RLock()
	c, ok := t.matchLocked(r)
	var handler http.Handler
	var hc *health.Checker
	if ok {
		handler = c.proxy
		hc = c.health
	} else {
		handler = t.fallback
		hc = t.fallbackHealth
	}
	errHandler := t.errHandler
	t.mu.RUnlock()

	if handler == nil {
		http.NotFound(w, r)
		return
	}
	if hc != nil && !hc.Healthy() {
		if errHandler != nil {
			errHandler(w, r, errUnhealthy)
			return
		}
		http.Error(w, "upstream unhealthy", http.StatusBadGateway)
		return
	}
	handler.ServeHTTP(w, r)
}

// Healthy reports whether the matched upstream (or fallback) is healthy.
func (t *Table) Healthy(r *http.Request) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	c, ok := t.matchLocked(r)
	if ok {
		if c.health == nil {
			return true
		}
		return c.health.Healthy()
	}
	if t.fallback != nil {
		if t.fallbackHealth == nil {
			return true
		}
		return t.fallbackHealth.Healthy()
	}
	return true
}

// HasRoutes reports whether any enabled routes are loaded.
func (t *Table) HasRoutes() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.compiled) > 0
}

// UpstreamHealth returns health by upstream id for status APIs.
func (t *Table) UpstreamHealth() map[string]bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[string]bool)
	seen := make(map[string]struct{})
	for _, c := range t.compiled {
		if _, ok := seen[c.upstream.ID]; ok {
			continue
		}
		seen[c.upstream.ID] = struct{}{}
		if c.health == nil {
			out[c.upstream.ID] = true
			continue
		}
		out[c.upstream.ID] = c.health.Healthy()
	}
	if t.fallbackHealth != nil {
		out["default"] = t.fallbackHealth.Healthy()
	}
	return out
}

func matchPrefix(path, prefix string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	if path == prefix {
		return true
	}
	trimmed := strings.TrimSuffix(prefix, "/")
	return path == trimmed || strings.HasPrefix(path, trimmed+"/")
}

func stripPort(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return host
	}
	if host[0] == '[' {
		if end := strings.IndexByte(host, ']'); end > 0 {
			return host[1:end]
		}
		return host
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		if strings.Count(host, ":") == 1 {
			return host[:i]
		}
	}
	return host
}

var errUnhealthy = &simpleError{"upstream unhealthy"}

type simpleError struct{ s string }

func (e *simpleError) Error() string { return e.s }

func parseDur(s string, def time.Duration) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}
