import type { Role } from './api'
import { canManageUsers } from './rbac'

export interface NavLinkSpec {
  path: string
  label: string
  requiresUserManage?: boolean
}

export const NAV_LINK_SPECS: NavLinkSpec[] = [
  { path: '/', label: 'Overview' },
  { path: '/proxies', label: 'Proxies' },
  { path: '/migrations', label: 'Move services' },
  { path: '/upstreams', label: 'Upstreams' },
  { path: '/routes', label: 'Routes' },
  { path: '/access', label: 'Access' },
  { path: '/certs', label: 'Certificates' },
  { path: '/logs', label: 'Logs' },
  { path: '/bans', label: 'Bans' },
  { path: '/blocklists', label: 'Blocklists' },
  { path: '/qfeeds', label: 'Q-Feeds' },
  { path: '/appearance', label: 'Appearance' },
  { path: '/config', label: 'Config' },
  { path: '/users', label: 'Users', requiresUserManage: true },
  { path: '/tokens', label: 'Tokens' },
  { path: '/audit', label: 'Audit' },
]

export function joinBasePath(basePath: string, path: string): string {
  const base = basePath.replace(/\/$/, '')
  if (path === '/') return `${base}/`
  return `${base}${path}`
}

export function isNavActive(pathname: string, href: string, basePath: string): boolean {
  const home = joinBasePath(basePath, '/')
  const base = basePath.replace(/\/$/, '')
  if (href === home || href === base) {
    return pathname === home || pathname === base
  }
  return pathname === href || pathname.startsWith(`${href}/`)
}

export function navLinkVisible(spec: NavLinkSpec, role: Role | undefined): boolean {
  if (spec.requiresUserManage) return canManageUsers(role)
  return true
}

export function visibleNavHrefs(basePath: string, role: Role | undefined): string[] {
  return NAV_LINK_SPECS.filter((spec) => navLinkVisible(spec, role)).map((spec) =>
    joinBasePath(basePath, spec.path),
  )
}
