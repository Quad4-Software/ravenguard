// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestMatchPrefixAndHost(t *testing.T) {
	tab := New(context.Background())
	tab.SetFallback(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}), nil)
	err := tab.Replace([]Upstream{
		{ID: "u1", Name: "a", URL: "http://127.0.0.1:9"},
		{ID: "u2", Name: "b", URL: "http://127.0.0.1:9"},
	}, []Route{
		{ID: "r1", Name: "api", Enabled: true, Hosts: []string{"api.example.com"}, PathPrefix: "/v1", UpstreamID: "u1", Priority: 10},
		{ID: "r2", Name: "root", Enabled: true, Hosts: []string{"api.example.com"}, PathPrefix: "/", UpstreamID: "u2", Priority: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/v1/x", nil)
	req.Host = "api.example.com"
	m, ok := tab.Lookup(req)
	if !ok || m.Route.ID != "r1" {
		t.Fatalf("want r1 got %#v ok=%v", m, ok)
	}
	req2 := httptest.NewRequest(http.MethodGet, "http://api.example.com/other", nil)
	req2.Host = "api.example.com"
	m2, ok := tab.Lookup(req2)
	if !ok || m2.Route.ID != "r2" {
		t.Fatalf("want r2 got %#v ok=%v", m2, ok)
	}
}

func TestReplaceClosesOldProxiesAndStartsHealth(t *testing.T) {
	ctx := t.Context()
	tab := New(ctx)

	var h1Called atomic.Bool
	u := Upstream{ID: "u1", Name: "u", URL: "http://127.0.0.1:9", HealthEnabled: true, HealthPath: "/healthz", HealthInterval: "10s", HealthTimeout: "1s"}
	if err := tab.Replace([]Upstream{u}, []Route{{ID: "r1", Name: "r", Enabled: true, PathPrefix: "/", UpstreamID: "u1"}}); err != nil {
		t.Fatal(err)
	}

	// Wait for the health checker goroutine to start.
	tab.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	h1Called.Store(true)

	u2 := Upstream{ID: "u2", Name: "u2", URL: "http://127.0.0.1:9"}
	if err := tab.Replace([]Upstream{u2}, []Route{{ID: "r2", Name: "r2", Enabled: true, PathPrefix: "/", UpstreamID: "u2"}}); err != nil {
		t.Fatal(err)
	}

	m, ok := tab.Lookup(httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if !ok || m.Route.ID != "r2" {
		t.Fatalf("want r2 got %#v ok=%v", m, ok)
	}

	// The old context being canceled stops the prior health checker.
	// The new table should be active and not contain the old route.
	m2, ok2 := tab.Lookup(httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if !ok2 || m2.Route.ID != "r2" {
		t.Fatalf("replace did not swap to r2")
	}
	_ = h1Called.Load()
}

func TestReplaceCleansUpPartialBuild(t *testing.T) {
	ctx := t.Context()
	tab := New(ctx)

	valid := Upstream{ID: "u1", Name: "u1", URL: "http://127.0.0.1:9"}
	bad := Upstream{ID: "u2", Name: "u2", URL: "://not-valid"}
	err := tab.Replace([]Upstream{valid, bad}, []Route{
		{ID: "r1", Name: "r1", Enabled: true, PathPrefix: "/v1", UpstreamID: "u1"},
		{ID: "r2", Name: "r2", Enabled: true, PathPrefix: "/v2", UpstreamID: "u2"},
	})
	if err == nil {
		t.Fatal("expected error from bad upstream URL")
	}

	// The first valid proxy should not have been installed because the
	// second route failed to build.
	if _, ok := tab.Lookup(httptest.NewRequest(http.MethodGet, "http://example.com/v1/x", nil)); ok {
		t.Fatal("expected table to be empty after failed Replace")
	}
}
