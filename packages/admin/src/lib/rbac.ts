import type { Role } from './api'

const rank: Record<Role, number> = {
  viewer: 1,
  admin: 2,
  owner: 3,
}

export function roleRank(role: Role | undefined): number {
  if (!role) return 0
  return rank[role] ?? 0
}

export function atLeast(role: Role | undefined, min: Role): boolean {
  return roleRank(role) >= roleRank(min)
}

export function canWriteOps(role: Role | undefined): boolean {
  return atLeast(role, 'admin')
}

export function canWriteConfig(role: Role | undefined): boolean {
  return atLeast(role, 'admin')
}

export function canManageUsers(role: Role | undefined): boolean {
  return atLeast(role, 'admin')
}

export function canManageOwners(role: Role | undefined): boolean {
  return role === 'owner'
}
