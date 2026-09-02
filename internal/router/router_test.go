// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package router

import (
	"context"
	"net/http"
	"net/http/httptest"
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
