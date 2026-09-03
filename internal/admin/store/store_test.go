// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/admin/auth"
	"github.com/Quad4-Software/ravenguard/internal/admin/rbac"
	"github.com/Quad4-Software/ravenguard/internal/admin/store"
)

func TestBootstrapAndSession(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	hash, err := auth.HashPassword("bootstrap-pass-1")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := st.BootstrapOwner("owner", hash)
	if err != nil {
		t.Fatal(err)
	}
	if owner.Role != rbac.RoleOwner {
		t.Fatalf("role=%s", owner.Role)
	}
	if _, err := st.BootstrapOwner("other", hash); err == nil {
		t.Fatal("expected second bootstrap to fail")
	}

	_, raw, csrf, exp, err := st.CreateSession(owner.ID, time.Hour, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || csrf == "" || exp.Before(time.Now()) {
		t.Fatalf("bad session raw/csrf/exp")
	}
	sess, u, err := st.GetSessionByToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "owner" || sess.CSRFToken != csrf {
		t.Fatalf("session mismatch")
	}

	before := sess.ExpiresAt
	newExp, newCSRF, err := st.ExtendSession(sess.ID, 2*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	if !newExp.After(before) {
		t.Fatalf("expected later expiry got %v before %v", newExp, before)
	}
	if newCSRF == "" || newCSRF == csrf {
		t.Fatal("expected rotated csrf")
	}
	sess2, _, err := st.GetSessionByToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	if sess2.CSRFToken != newCSRF {
		t.Fatalf("csrf not persisted")
	}

	sessID, raw2, _, _, err := st.CreateSession(owner.ID, time.Hour, "10.0.0.2", "other-ua")
	if err != nil {
		t.Fatal(err)
	}
	list, err := st.ListSessionsForUser(owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 sessions got %d", len(list))
	}
	if err := st.DeleteSessionForUser(owner.ID, sessID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.GetSessionByToken(raw2); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want revoked session not found got %v", err)
	}
	if err := st.DeleteSessionForUser(owner.ID, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want not found got %v", err)
	}
}

func TestLastOwnerGuard(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	hash, _ := auth.HashPassword("bootstrap-pass-1")
	owner, err := st.BootstrapOwner("owner", hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUser(owner.ID); !errors.Is(err, store.ErrLastOwner) {
		t.Fatalf("want ErrLastOwner got %v", err)
	}
	dis := true
	if _, err := st.UpdateUser(owner.ID, rbac.RoleAdmin, &dis); !errors.Is(err, store.ErrLastOwner) {
		t.Fatalf("want ErrLastOwner got %v", err)
	}
}

func TestAPITokenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	hash, _ := auth.HashPassword("bootstrap-pass-1")
	owner, _ := st.BootstrapOwner("owner", hash)
	tok, raw, err := st.CreateAPIToken(owner.ID, "ci", rbac.RoleAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, u, err := st.LookupAPIToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != tok.ID || u.ID != owner.ID {
		t.Fatalf("lookup mismatch")
	}
	if err := st.RevokeAPIToken(tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.LookupAPIToken(raw); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want not found after revoke")
	}
}
