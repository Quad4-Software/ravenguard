// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/access"
	"github.com/Quad4-Software/ravenguard/internal/admin/auth"
	"github.com/Quad4-Software/ravenguard/internal/admin/rbac"
	"github.com/Quad4-Software/ravenguard/internal/admin/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestUsersCRUD(t *testing.T) {
	st := openStore(t)
	hash, err := auth.HashPassword("bootstrap-pass-1")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := st.BootstrapOwner("owner", hash)
	if err != nil {
		t.Fatal(err)
	}
	adminHash, _ := auth.HashPassword("admin-pass-12")
	admin, err := st.CreateUser("admin", adminHash, rbac.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser("admin", adminHash, rbac.RoleViewer); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("want conflict got %v", err)
	}
	if _, err := st.CreateUser("", adminHash, rbac.RoleViewer); !errors.Is(err, store.ErrInvalidUser) {
		t.Fatalf("want invalid user got %v", err)
	}
	if _, err := st.CreateUser("x", adminHash, "nope"); !errors.Is(err, store.ErrInvalidRole) {
		t.Fatalf("want invalid role got %v", err)
	}

	got, err := st.GetUserByName("OWNER")
	if err != nil || got.ID != owner.ID {
		t.Fatalf("get by name: %v %#v", err, got)
	}
	list, err := st.ListUsers()
	if err != nil || len(list) != 2 {
		t.Fatalf("list=%d err=%v", len(list), err)
	}
	n, err := st.CountUsers()
	if err != nil || n != 2 {
		t.Fatalf("count=%d err=%v", n, err)
	}

	viewer, err := st.UpdateUser(admin.ID, rbac.RoleViewer, nil)
	if err != nil || viewer.Role != rbac.RoleViewer {
		t.Fatalf("update role: %v %#v", err, viewer)
	}
	dis := false
	if _, err := st.UpdateUser(admin.ID, "", &dis); err != nil {
		t.Fatal(err)
	}
	renamed, err := st.SetUsername(admin.ID, "ops")
	if err != nil || renamed.Username != "ops" {
		t.Fatalf("rename: %v %#v", err, renamed)
	}
	if _, err := st.SetUsername(admin.ID, "owner"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("want rename conflict got %v", err)
	}
	newHash, _ := auth.HashPassword("new-admin-pass")
	if err := st.SetPassword(admin.ID, newHash); err != nil {
		t.Fatal(err)
	}
	if err := st.SetPassword(9999, newHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want not found got %v", err)
	}
	if err := st.DeleteUser(admin.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetUser(admin.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want deleted got %v", err)
	}
}

func TestUpstreamRouteAccessAndAudit(t *testing.T) {
	st := openStore(t)
	hash, _ := auth.HashPassword("bootstrap-pass-1")
	owner, err := st.BootstrapOwner("owner", hash)
	if err != nil {
		t.Fatal(err)
	}

	up, err := st.CreateUpstream(store.UpstreamRow{
		Name:          "app",
		URL:           "http://127.0.0.1:8080",
		HealthEnabled: true,
		SetHeaders:    []string{"X-RG: 1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if up.HealthPath == "" || up.ID == "" {
		t.Fatalf("upstream defaults missing %#v", up)
	}
	listed, err := st.ListUpstreams()
	if err != nil || len(listed) != 1 {
		t.Fatalf("list upstreams=%d err=%v", len(listed), err)
	}
	up2, err := st.UpdateUpstream(up.ID, store.UpstreamRow{
		Name: "app2",
		URL:  "http://127.0.0.1:8081",
	})
	if err != nil || up2.Name != "app2" {
		t.Fatalf("update upstream: %v %#v", err, up2)
	}
	if n, err := st.CountUpstreams(); err != nil || n != 1 {
		t.Fatalf("count upstreams=%d err=%v", n, err)
	}

	pol, err := st.CreateAccessPolicy(store.AccessPolicyRow{
		Name: "gate",
		Mode: access.ModeAll,
		Rules: []access.Rule{{
			Type:   access.RulePassword,
			Secret: "super-secret-1",
		}},
		CookieTTL: "1h",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.Rules) != 1 || pol.Rules[0].Secret != "" || pol.Rules[0].SecretHash == "" {
		t.Fatalf("expected hashed secret %#v", pol)
	}
	pols, err := st.ListAccessPolicies()
	if err != nil || len(pols) != 1 {
		t.Fatalf("list policies=%d err=%v", len(pols), err)
	}
	pol2, err := st.UpdateAccessPolicy(pol.ID, store.AccessPolicyRow{
		Name: "gate2",
		Mode: access.ModeAny,
		Rules: []access.Rule{{
			Type:   access.RulePIN,
			Secret: "123456",
		}},
	})
	if err != nil || pol2.Name != "gate2" {
		t.Fatalf("update policy: %v %#v", err, pol2)
	}

	polID := pol2.ID
	rt, err := st.CreateRoute(store.RouteRow{
		Name:           "main",
		Enabled:        true,
		Hosts:          []string{"example.test"},
		PathPrefix:     "/",
		UpstreamID:     up.ID,
		Priority:       10,
		AccessPolicyID: &polID,
	})
	if err != nil {
		t.Fatal(err)
	}
	routes, err := st.ListRoutes()
	if err != nil || len(routes) != 1 {
		t.Fatalf("list routes=%d err=%v", len(routes), err)
	}
	rt2, err := st.UpdateRoute(rt.ID, store.RouteRow{
		Name:       "main2",
		Enabled:    true,
		Hosts:      []string{"example.test", "www.example.test"},
		PathPrefix: "/app",
		UpstreamID: up.ID,
		Priority:   5,
	})
	if err != nil || rt2.Name != "main2" || len(rt2.Hosts) != 2 {
		t.Fatalf("update route: %v %#v", err, rt2)
	}

	if err := st.DeleteUpstream(up.ID); !errors.Is(err, store.ErrInUse) {
		t.Fatalf("want in use got %v", err)
	}
	if err := st.DeleteRoute(rt.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAccessPolicy(pol.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUpstream(up.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetUpstream(up.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want upstream gone got %v", err)
	}

	actor := owner.ID
	if err := st.AppendAudit(&actor, owner.Username, "test.action", "target", "detail", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	events, err := st.ListAudit(0, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("audit=%d err=%v", len(events), err)
	}
	more, err := st.ListAudit(events[0].ID, 10)
	if err != nil || len(more) != 0 {
		t.Fatalf("audit page=%d err=%v", len(more), err)
	}

	if err := st.SetConfigOverrides(`{"ui":{"brand":"x"}}`, owner.ID); err != nil {
		t.Fatal(err)
	}
	payload, err := st.GetConfigOverrides()
	if err != nil || payload == "" || payload == "{}" {
		t.Fatalf("overrides=%q err=%v", payload, err)
	}

	exp := time.Now().UTC().Add(time.Hour)
	tok, raw, err := st.CreateAPIToken(owner.ID, "ci", rbac.RoleViewer, &exp)
	if err != nil {
		t.Fatal(err)
	}
	if tok.ID == "" || raw == "" {
		t.Fatal("empty token")
	}
	tokens, err := st.ListAPITokens(owner.ID, false)
	if err != nil || len(tokens) < 1 {
		t.Fatalf("list tokens=%d err=%v", len(tokens), err)
	}
	got, err := st.GetAPIToken(tok.ID)
	if err != nil || got.Name != "ci" {
		t.Fatalf("get token: %v %#v", err, got)
	}
}

func TestExtendSessionWithoutRotate(t *testing.T) {
	st := openStore(t)
	hash, _ := auth.HashPassword("bootstrap-pass-1")
	owner, err := st.BootstrapOwner("owner", hash)
	if err != nil {
		t.Fatal(err)
	}
	sessID, raw, csrf, _, err := st.CreateSession(owner.ID, time.Hour, "127.0.0.1", "ua")
	if err != nil {
		t.Fatal(err)
	}
	exp, gotCSRF, err := st.ExtendSession(sessID, 3*time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if gotCSRF != csrf {
		t.Fatalf("csrf changed without rotate")
	}
	if !exp.After(time.Now()) {
		t.Fatal("bad expiry")
	}
	if err := st.DeleteSessionsForUser(owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.GetSessionByToken(raw); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want revoked got %v", err)
	}
	if _, _, err := st.ExtendSession("missing", time.Hour, true); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want not found got %v", err)
	}
}
