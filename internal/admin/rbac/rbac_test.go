// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package rbac_test

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/admin/rbac"
)

func TestValidRoleAndNormalize(t *testing.T) {
	if !rbac.ValidRole(" Owner ") || !rbac.ValidRole("ADMIN") || !rbac.ValidRole("viewer") {
		t.Fatal("expected valid roles")
	}
	if rbac.ValidRole("") || rbac.ValidRole("root") {
		t.Fatal("expected invalid roles")
	}
	if got := rbac.Normalize(" AdMiN "); got != rbac.RoleAdmin {
		t.Fatalf("normalize=%q", got)
	}
}

func TestRankAndCapabilities(t *testing.T) {
	if rbac.Rank(rbac.RoleOwner) <= rbac.Rank(rbac.RoleAdmin) {
		t.Fatal("owner should outrank admin")
	}
	if rbac.Rank("nope") != 0 {
		t.Fatal("unknown rank want 0")
	}
	if !rbac.AtLeast(rbac.RoleAdmin, rbac.RoleViewer) {
		t.Fatal("admin should satisfy viewer")
	}
	if rbac.AtLeast(rbac.RoleViewer, rbac.RoleAdmin) {
		t.Fatal("viewer should not satisfy admin")
	}
	if !rbac.CanManageUsers(rbac.RoleAdmin) || rbac.CanManageUsers(rbac.RoleViewer) {
		t.Fatal("manage users")
	}
	if !rbac.CanManageOwners(rbac.RoleOwner) || rbac.CanManageOwners(rbac.RoleAdmin) {
		t.Fatal("manage owners")
	}
	if !rbac.CanWriteOps(rbac.RoleAdmin) || !rbac.CanWriteConfig(rbac.RoleOwner) {
		t.Fatal("write ops/config")
	}
	if !rbac.CanRead(rbac.RoleViewer) || rbac.CanRead("") {
		t.Fatal("read")
	}
}
