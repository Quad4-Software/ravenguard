// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package api

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/admin/ops"
	"github.com/Quad4-Software/ravenguard/internal/admin/store"
	"github.com/Quad4-Software/ravenguard/internal/config"
)

func TestBuildDesiredStateAndHelpers(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	proxy, _, err := st.CreateProxy("edge", nil, "1.2.3.4", "", false)
	if err != nil {
		t.Fatal(err)
	}
	up, err := st.CreateUpstream(store.UpstreamRow{Name: "u1", URL: "http://127.0.0.1:9"})
	if err != nil {
		t.Fatal(err)
	}
	pol, err := st.CreateAccessPolicy(store.AccessPolicyRow{Name: "p1", Mode: "open"})
	if err != nil {
		t.Fatal(err)
	}
	polID := pol.ID
	_, err = st.CreateRoute(store.RouteRow{
		Name:           "web",
		Enabled:        true,
		Hosts:          []string{"app.example", "*", "app.example"},
		PathPrefix:     "/",
		UpstreamID:     up.ID,
		AccessPolicyID: &polID,
		ProxyID:        proxy.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetFleetDefaults(`{"challenge":{"mode":"off"}}`); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	s := &Server{Store: st, Runtime: ops.NewRuntime(cfg, nil, nil, nil, nil, nil, nil)}
	state, err := s.BuildDesiredState(proxy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision < 1 || len(state.ACMEHosts) != 1 || state.ACMEHosts[0] != "app.example" {
		t.Fatalf("%+v", state)
	}
	if len(state.Routing) == 0 || len(state.SafeConfig) == 0 {
		t.Fatalf("expected routing and safe config: %+v", state)
	}

	if _, err := findUpstream(nil, "x"); err == nil {
		t.Fatal("expected missing upstream")
	}
	if _, err := findPolicy(nil, "x"); err == nil {
		t.Fatal("expected missing policy")
	}
	got := uniqueStrings([]string{"a", "a", "b", "a"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("%v", got)
	}
}

func TestBuildDNSChecklist(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	up, err := st.CreateUpstream(store.UpstreamRow{Name: "u", URL: "http://127.0.0.1:9"})
	if err != nil {
		t.Fatal(err)
	}
	rt, err := st.CreateRoute(store.RouteRow{
		Name: "r", Enabled: true, Hosts: []string{"a.example", "*"}, PathPrefix: "/", UpstreamID: up.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	from := store.ProxyRow{PublicIPv4: "1.1.1.1"}
	to := store.ProxyRow{PublicIPv4: "2.2.2.2", PublicIPv6: "2001:db8::1"}
	items := buildDNSChecklist([]string{rt.ID, "missing"}, from, to, st)
	if len(items) != 1 || items[0].Host != "a.example" || items[0].SuggestedA != "2.2.2.2" {
		t.Fatalf("%+v", items)
	}
	if items[0].SuggestedAAAA != "2001:db8::1" {
		t.Fatalf("%+v", items)
	}
}
