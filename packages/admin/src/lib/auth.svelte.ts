import { api, APIError, setCSRFToken, type User } from './api'

class AuthStore {
  user = $state<User | null>(null)
  tokenAuth = $state(false)
  ready = $state(false)
  pending = $state(false)

  get loggedIn() {
    return this.user !== null
  }

  get role() {
    return this.user?.role
  }

  async restore() {
    try {
      const session = await api.auth.me()
      this.user = session.user
      this.tokenAuth = Boolean(session.token_auth)
      setCSRFToken(session.csrf_token)
    } catch {
      this.user = null
      setCSRFToken('')
    } finally {
      this.ready = true
    }
  }

  async login(username: string, password: string) {
    this.pending = true
    try {
      const res = await api.auth.login(username, password)
      this.user = res.user
      setCSRFToken(res.csrf_token)
    } finally {
      this.pending = false
    }
  }

  async logout() {
    try {
      await api.auth.logout()
    } catch (err) {
      if (!(err instanceof APIError)) throw err
    } finally {
      this.user = null
      setCSRFToken('')
    }
  }
}

export const auth = new AuthStore()
