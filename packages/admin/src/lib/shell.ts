/** Viewport width at or below this uses the mobile shell (drawer nav). */
export const SHELL_MOBILE_MAX_PX = 860

export type NavAction = 'open' | 'close' | 'toggle'

export function isShellMobileViewport(width: number, maxPx = SHELL_MOBILE_MAX_PX): boolean {
  return width <= maxPx
}

export function nextNavOpen(current: boolean, action: NavAction): boolean {
  if (action === 'open') return true
  if (action === 'close') return false
  return !current
}

export function shouldCloseNavOnNavigate(isMobile: boolean): boolean {
  return isMobile
}

export function shouldLockBodyScroll(navOpen: boolean, isMobile: boolean): boolean {
  return navOpen && isMobile
}
