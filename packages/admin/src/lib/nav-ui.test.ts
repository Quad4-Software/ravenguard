import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  NAV_LINK_SPECS,
  isNavActive,
  joinBasePath,
  navLinkVisible,
  visibleNavHrefs,
} from './nav'
import {
  SHELL_MOBILE_MAX_PX,
  isShellMobileViewport,
  nextNavOpen,
  shouldCloseNavOnNavigate,
  shouldLockBodyScroll,
} from './shell'

const here = dirname(fileURLToPath(import.meta.url))
const appCss = readFileSync(join(here, '../app.css'), 'utf8')
const layoutSrc = readFileSync(join(here, '../routes/+layout.svelte'), 'utf8')
const navSrc = readFileSync(join(here, './components/Nav.svelte'), 'utf8')

describe('isNavActive', () => {
  it('treats base home paths as overview', () => {
    expect(isNavActive('/', joinBasePath('', '/'), '')).toBe(true)
    expect(isNavActive('/admin', joinBasePath('/admin', '/'), '/admin')).toBe(true)
    expect(isNavActive('/admin/', joinBasePath('/admin', '/'), '/admin')).toBe(true)
  })

  it('matches nested routes under a section', () => {
    const href = joinBasePath('', '/proxies')
    expect(isNavActive('/proxies', href, '')).toBe(true)
    expect(isNavActive('/proxies/abc', href, '')).toBe(true)
    expect(isNavActive('/proxy', href, '')).toBe(false)
  })

  it('does not mark overview active on other pages', () => {
    expect(isNavActive('/logs', joinBasePath('', '/'), '')).toBe(false)
  })
})

describe('nav visibility', () => {
  it('hides Users for viewers and shows it for admins', () => {
    const users = NAV_LINK_SPECS.find((s) => s.path === '/users')
    expect(users).toBeDefined()
    expect(navLinkVisible(users!, 'viewer')).toBe(false)
    expect(navLinkVisible(users!, 'admin')).toBe(true)
    expect(navLinkVisible(users!, 'owner')).toBe(true)
  })

  it('always shows non-gated links', () => {
    const overview = NAV_LINK_SPECS.find((s) => s.path === '/')
    expect(navLinkVisible(overview!, 'viewer')).toBe(true)
  })

  it('builds visible hrefs without Users for viewers', () => {
    const hrefs = visibleNavHrefs('', 'viewer')
    expect(hrefs).toContain('/')
    expect(hrefs).toContain('/proxies')
    expect(hrefs).not.toContain('/users')
  })

  it('includes Users for admins', () => {
    expect(visibleNavHrefs('/admin', 'admin')).toContain('/admin/users')
  })
})

describe('shell mobile helpers', () => {
  it('uses the shared mobile breakpoint', () => {
    expect(SHELL_MOBILE_MAX_PX).toBe(860)
    expect(isShellMobileViewport(860)).toBe(true)
    expect(isShellMobileViewport(861)).toBe(false)
  })

  it('toggles drawer open state', () => {
    expect(nextNavOpen(false, 'open')).toBe(true)
    expect(nextNavOpen(true, 'close')).toBe(false)
    expect(nextNavOpen(false, 'toggle')).toBe(true)
    expect(nextNavOpen(true, 'toggle')).toBe(false)
  })

  it('closes the drawer after navigate only on mobile', () => {
    expect(shouldCloseNavOnNavigate(true)).toBe(true)
    expect(shouldCloseNavOnNavigate(false)).toBe(false)
  })

  it('locks body scroll only when the mobile drawer is open', () => {
    expect(shouldLockBodyScroll(true, true)).toBe(true)
    expect(shouldLockBodyScroll(true, false)).toBe(false)
    expect(shouldLockBodyScroll(false, true)).toBe(false)
  })
})

describe('admin shell UI contract', () => {
  it('keeps CSS mobile breakpoint aligned with SHELL_MOBILE_MAX_PX', () => {
    expect(appCss).toContain(`@media (max-width: ${SHELL_MOBILE_MAX_PX}px)`)
    expect(appCss).toContain('.shell-top')
    expect(appCss).toContain('.shell-backdrop')
    expect(appCss).toContain('.shell.nav-open .shell-nav')
    expect(appCss).toContain('transform: translateX(-105%)')
  })

  it('uses slightly larger sidebar link sizing', () => {
    expect(appCss).toMatch(/\.nav-link\s*\{[^}]*font-size:\s*0\.9rem/s)
    expect(appCss).toMatch(/\.nav-link\s*\{[^}]*padding:\s*0\.5rem 1\.15rem/s)
    expect(appCss).toMatch(/\.nav-link-icon\s*\{[^}]*width:\s*1\.125rem/s)
    expect(appCss).toContain('grid-template-columns: 15.75rem minmax(0, 1fr)')
  })

  it('wires a mobile menu button and drawer controls in the layout', () => {
    expect(layoutSrc).toContain('shell-menu-btn')
    expect(layoutSrc).toContain('aria-controls="admin-nav"')
    expect(layoutSrc).toContain('shell.toggleNav()')
    expect(layoutSrc).toContain('shell.closeNav()')
    expect(layoutSrc).toContain('Escape')
    expect(layoutSrc).toContain('SHELL_MOBILE_MAX_PX')
    expect(layoutSrc).toContain('class:nav-open={shell.navOpen}')
  })

  it('closes the drawer from nav links and uses larger icons', () => {
    expect(navSrc).toContain('id="admin-nav"')
    expect(navSrc).toContain('shell.closeNav()')
    expect(navSrc).toContain('size={18}')
    expect(navSrc).toContain('NAV_LINK_SPECS')
  })

  it('shows hub build version from status in the sidebar', () => {
    expect(navSrc).toContain('nav-version')
    expect(navSrc).toContain('api.status')
    expect(navSrc).toContain('versionLabel')
  })
})
