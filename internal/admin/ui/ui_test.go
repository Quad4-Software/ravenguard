// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPICall(t *testing.T) {
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user":{"id":1,"username":"admin","role":"owner"}}`))
	})

	u, err := New(apiMux, "/")
	if err != nil {
		t.Fatalf("new ui: %v", err)
	}

	r := httptest.NewRequest(http.MethodPost, "/login", nil)
	status, body, _, err := u.apiCall(r, http.MethodPost, "/auth/login", map[string]any{"username": "admin"}, "application/json")
	if err != nil {
		t.Fatalf("apiCall error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d, body: %s", status, string(body))
	}
}

// TestLoginAndOverviewVector asserts that the UI makes the expected internal
// API calls for login and the overview page. This is the parity vector used to
// prove the HTMX rewrite is wired 1:1 against the JSON API.
func TestLoginAndOverviewVector(t *testing.T) {
	called := make(map[string]int)
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		called["POST /api/v1/auth/login"]++
		w.Header().Set("Set-Cookie", "rg_admin_session=dummy; Path=/; HttpOnly; SameSite=Strict")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user":{"id":1,"username":"admin","role":"owner"},"csrf_token":"tok","expires_at":"2026-09-10T10:00:00Z"}`))
	})
	apiMux.HandleFunc("/api/v1/auth/me", func(w http.ResponseWriter, r *http.Request) {
		called["GET /api/v1/auth/me"]++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user":{"id":1,"username":"admin","role":"owner"},"csrf_token":"tok"}`))
	})
	apiMux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		called["GET /api/v1/status"]++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"uptime_seconds":100,"upstream_healthy":true,"ban_count":0,"concurrency_global":1,"concurrency_clients":1,"ratelimit_buckets":0,"blocklists":{"ip_count":4,"dns_count":2,"ua_count":77,"last_reload":"2026-09-10T05:01:16.27976321-05:00"},"challenge_enabled":true,"qfeeds_enabled":false,"qfeeds":{"enabled":false,"failed":false,"ip_count":0,"domain_count":0},"protect_enabled":true,"ratelimit_enabled":true,"detect_enabled":true,"process":{"cpu_percent":0.2,"goroutines":28,"gomaxprocs":12,"num_cpu":12,"heap_alloc_bytes":140155864,"heap_sys_bytes":217120768,"sys_bytes":226060600,"rss_bytes":226060600,"gc_pause_ns":928701,"num_gc":7}}`))
	})
	apiMux.HandleFunc("/api/v1/status/history", func(w http.ResponseWriter, r *http.Request) {
		called["GET /api/v1/status/history"]++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"samples":[{"cpu_percent":0.1}]}`))
	})

	u, err := New(apiMux, "/")
	if err != nil {
		t.Fatalf("new ui: %v", err)
	}

	// POST login -> redirects to /.
	body1 := strings.NewReader("username=admin&password=secret")
	r1 := httptest.NewRequest(http.MethodPost, "/login", body1)
	r1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w1 := httptest.NewRecorder()
	u.route(w1, r1)
	if w1.Code != http.StatusFound || w1.Header().Get("Location") != "/" {
		t.Fatalf("expected 302 to /, got %d %s", w1.Code, w1.Header().Get("Location"))
	}

	// GET / requires auth and then status + history.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("Cookie", "rg_admin_session=dummy")
	w2 := httptest.NewRecorder()
	u.route(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected overview 200, got %d: %s", w2.Code, w2.Body.String())
	}
	body := w2.Body.String()
	if !strings.Contains(body, "Process load") {
		t.Fatalf("overview missing expected content: %s", body)
	}

	want := map[string]int{
		"POST /api/v1/auth/login":    1,
		"GET /api/v1/auth/me":        1,
		"GET /api/v1/status":         1,
		"GET /api/v1/status/history": 1,
	}
	for k, v := range want {
		if called[k] != v {
			t.Fatalf("expected %q called %d times, got %d", k, v, called[k])
		}
	}
}
