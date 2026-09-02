import { describe, expect, it } from 'vitest'
import { atLeast, canManageOwners, canManageUsers, canWriteConfig, canWriteOps, roleRank } from './rbac'

describe('roleRank', () => {
  it('ranks owner above admin above viewer', () => {
    expect(roleRank('owner')).toBeGreaterThan(roleRank('admin'))
    expect(roleRank('admin')).toBeGreaterThan(roleRank('viewer'))
  })

  it('ranks a missing role as zero', () => {
    expect(roleRank(undefined)).toBe(0)
  })
})

describe('atLeast', () => {
  it('allows equal or higher roles', () => {
    expect(atLeast('admin', 'admin')).toBe(true)
    expect(atLeast('owner', 'admin')).toBe(true)
  })

  it('rejects lower roles', () => {
    expect(atLeast('viewer', 'admin')).toBe(false)
    expect(atLeast(undefined, 'viewer')).toBe(false)
  })
})

describe('role gates', () => {
  it('requires admin or higher for ops writes and config writes', () => {
    expect(canWriteOps('viewer')).toBe(false)
    expect(canWriteOps('admin')).toBe(true)
    expect(canWriteConfig('owner')).toBe(true)
  })

  it('requires admin or higher to manage users', () => {
    expect(canManageUsers('viewer')).toBe(false)
    expect(canManageUsers('admin')).toBe(true)
  })

  it('restricts owner management to owners only', () => {
    expect(canManageOwners('admin')).toBe(false)
    expect(canManageOwners('owner')).toBe(true)
  })
})
