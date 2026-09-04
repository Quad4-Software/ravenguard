// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

func TestProxyFleetCRUDAndDesired(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	row, token, err := st.CreateProxy("edge-1", []string{"prod"}, "1.2.3.4", "2001:db8::1", false)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || row.ID == "" {
		t.Fatal("missing enrollment")
	}
	list, err := st.ListProxies()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %d", err, len(list))
	}
	got, err := st.GetProxy(row.ID)
	if err != nil || got.Name != "edge-1" {
		t.Fatalf("get: %+v %v", got, err)
	}
	updated, err := st.UpdateProxy(row.ID, "edge-1b", []string{"edge"}, "9.9.9.9", "")
	if err != nil || updated.Name != "edge-1b" || updated.PublicIPv4 != "9.9.9.9" {
		t.Fatalf("update: %+v %v", updated, err)
	}
	pid, fp, name, uni, err := st.LookupToken(agentprotocol.HashToken(token))
	if err != nil || pid != row.ID || name == "" || uni {
		t.Fatalf("lookup: %s %s %s %v %v", pid, fp, name, uni, err)
	}
	if err := st.BindFingerprint(row.ID, "fp1234567890abcdef1234567890abcdef", "edge-1b", "host1"); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchProxy(row.ID, ":80", ":443", ""); err != nil {
		t.Fatal(err)
	}
	state := agentprotocol.DesiredState{Revision: 1, SafeConfig: []byte(`{"a":1}`)}
	if err := st.SetDesiredState(row.ID, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := st.DesiredState(row.ID)
	if err != nil || loaded.Revision != 1 {
		t.Fatalf("desired: %+v %v", loaded, err)
	}
	rev, err := st.DesiredRevision(row.ID)
	if err != nil || rev != 1 {
		t.Fatalf("rev %d %v", rev, err)
	}
	next, err := st.NextDesiredRevision(row.ID)
	if err != nil || next != 2 {
		t.Fatalf("next %d %v", next, err)
	}
	if err := st.SetFleetDefaults(`{"rate_limit":{}}`); err != nil {
		t.Fatal(err)
	}
	defs, err := st.GetFleetDefaults()
	if err != nil || defs == "" {
		t.Fatalf("defaults %q %v", defs, err)
	}
	rotated, newTok, err := st.RotateProxyToken(row.ID)
	if err != nil || newTok == "" || rotated.EnrollmentToken == "" {
		t.Fatalf("rotate: %+v %v", rotated, err)
	}
	if _, _, _, _, err := st.LookupToken(agentprotocol.HashToken(token)); err == nil {
		t.Fatal("old token should be invalid")
	}
	if err := st.DeleteProxy(row.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetProxy(row.ID); err == nil {
		t.Fatal("expected not found")
	}
}

func TestServiceMigrationLifecycle(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	from, _, err := st.CreateProxy("from", nil, "1.1.1.1", "", false)
	if err != nil {
		t.Fatal(err)
	}
	to, _, err := st.CreateProxy("to", nil, "2.2.2.2", "", false)
	if err != nil {
		t.Fatal(err)
	}
	up, err := st.CreateUpstream(UpstreamRow{Name: "u", URL: "http://127.0.0.1:9"})
	if err != nil {
		t.Fatal(err)
	}
	rt, err := st.CreateRoute(RouteRow{
		Name:       "r1",
		Enabled:    true,
		Hosts:      []string{"app.example"},
		PathPrefix: "/",
		UpstreamID: up.ID,
		ProxyID:    from.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	by := 1
	m, err := st.CreateServiceMigration(from.ID, to.ID, []string{rt.ID}, &by, []DNSChecklistItem{
		{Host: "app.example", SuggestedA: "2.2.2.2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.Phase != "created" || len(m.RouteIDs) != 1 {
		t.Fatalf("%+v", m)
	}
	list, err := st.ListServiceMigrations()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %d", err, len(list))
	}
	m2, err := st.UpdateServiceMigration(m.ID, "prepared", "ready", []DNSChecklistItem{
		{Host: "app.example", SuggestedA: "2.2.2.2", Note: "ok"},
	})
	if err != nil || m2.Phase != "prepared" {
		t.Fatalf("%+v %v", m2, err)
	}
	m3, err := st.UpdateServiceMigration(m.ID, "completed", "done", nil)
	if err != nil || m3.Phase != "completed" {
		t.Fatalf("%+v %v", m3, err)
	}
	if err := st.SetRouteProxy(rt.ID, to.ID); err != nil {
		t.Fatal(err)
	}
	routes, err := st.ListRoutesForProxy(to.ID)
	if err != nil || len(routes) != 1 {
		t.Fatalf("routes: %v %d", err, len(routes))
	}
}
