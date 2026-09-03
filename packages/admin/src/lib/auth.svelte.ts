import { api, APIError, setCSRFToken, type User } from './api'

const minRefreshMs = 5 * 60 * 1000

class AuthStore {
  user = $state<User | null>(null)
  tokenAuth = $state(false)
  ready = $state(false)
  pending = $state(false)
  expiresAt = $state<string | null>(null)

  #refreshTimer: ReturnType<typeof setTimeout> | undefined
  #visibilityBound = false

  get loggedIn() {
    return this.user !== null
  }

  get role() {
    return this.user?.role
  }

  async restore() {
    try {
      const session = await api.auth.me()
      this.applySession(session.user, session.csrf_token, Boolean(session.token_auth), session.expires_at)
    } catch {
      this.clearSession()
    } finally {
      this.ready = true
    }
  }

  async login(username: string, password: string) {
    this.pending = true
    try {
      const res = await api.auth.login(username, password)
      this.applySession(res.user, res.csrf_token, false, res.expires_at)
    } finally {
      this.pending = false
    }
  }

  async logout() {
    this.clearRefreshTimer()
    try {
      await api.auth.logout()
    } catch (err) {
      if (!(err instanceof APIError)) throw err
    } finally {
      this.clearSession()
    }
  }

  async refreshSession(): Promise<boolean> {
    if (!this.loggedIn || this.tokenAuth) return false
    try {
      const res = await api.auth.refresh()
      this.applySession(res.user, res.csrf_token, false, res.expires_at)
      return true
    } catch (err) {
      if (err instanceof APIError && (err.status === 401 || err.status === 403)) {
        this.clearSession()
      }
      return false
    }
  }

  applySession(user: User, csrf: string, tokenAuth: boolean, expiresAt?: string) {
    this.user = user
    this.tokenAuth = tokenAuth
    this.expiresAt = expiresAt ?? null
    setCSRFToken(csrf)
    this.scheduleRefresh()
    this.bindVisibility()
  }

  clearSession() {
    this.clearRefreshTimer()
    this.user = null
    this.tokenAuth = false
    this.expiresAt = null
    setCSRFToken('')
  }

  scheduleRefresh() {
    this.clearRefreshTimer()
    if (!this.loggedIn || this.tokenAuth || !this.expiresAt) return
    const expMs = Date.parse(this.expiresAt)
    if (!Number.isFinite(expMs)) return
    const remaining = expMs - Date.now()
    if (remaining <= 0) {
      void this.refreshSession()
      return
    }
    const delay = Math.max(minRefreshMs, Math.floor(remaining / 2))
    this.#refreshTimer = setTimeout(() => {
      void this.refreshSession()
    }, delay)
  }

  clearRefreshTimer() {
    if (this.#refreshTimer) {
      clearTimeout(this.#refreshTimer)
      this.#refreshTimer = undefined
    }
  }

  bindVisibility() {
    if (this.#visibilityBound || typeof document === 'undefined') return
    this.#visibilityBound = true
    document.addEventListener('visibilitychange', () => {
      if (document.hidden || !this.loggedIn || this.tokenAuth || !this.expiresAt) return
      const expMs = Date.parse(this.expiresAt)
      if (!Number.isFinite(expMs)) return
      const remaining = expMs - Date.now()
      if (remaining <= minRefreshMs * 2) {
        void this.refreshSession()
      }
    })
  }
}

export const auth = new AuthStore()
