// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package rbac

import "strings"

const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

func ValidRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case RoleOwner, RoleAdmin, RoleViewer:
		return true
	default:
		return false
	}
}

func Normalize(role string) string {
	return strings.ToLower(strings.TrimSpace(role))
}

func Rank(role string) int {
	switch Normalize(role) {
	case RoleOwner:
		return 3
	case RoleAdmin:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

func AtLeast(role, minimum string) bool {
	return Rank(role) >= Rank(minimum)
}

func CanManageUsers(actorRole string) bool {
	return AtLeast(actorRole, RoleAdmin)
}

func CanManageOwners(actorRole string) bool {
	return Normalize(actorRole) == RoleOwner
}

func CanWriteOps(actorRole string) bool {
	return AtLeast(actorRole, RoleAdmin)
}

func CanWriteConfig(actorRole string) bool {
	return AtLeast(actorRole, RoleAdmin)
}

func CanRead(actorRole string) bool {
	return AtLeast(actorRole, RoleViewer)
}
