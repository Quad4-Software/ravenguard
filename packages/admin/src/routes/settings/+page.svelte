<script lang="ts">
  import { onMount } from 'svelte'
  import { auth } from '$lib/auth.svelte'
  import { api, APIError, type AuthSession } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { goto } from '$app/navigation'
  import { base } from '$app/paths'
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte'

  let username = $state('')
  let currentPassword = $state('')
  let newPassword = $state('')
  let confirmPassword = $state('')
  let savingUser = $state(false)
  let savingPass = $state(false)
  let refreshing = $state(false)
  let sessions = $state<AuthSession[]>([])
  let sessionsLoading = $state(true)
  let sessionsError = $state('')
  let confirmRevoke = $state<AuthSession | null>(null)
  let confirmRevokeAll = $state(false)
  let revoking = $state(false)

  const expiresLabel = $derived.by(() => formatWhen(auth.expiresAt))

  const otherSessionCount = $derived(sessions.filter((s) => !s.current).length)

  function formatWhen(value?: string | null): string {
    if (!value) return 'unknown'
    const ms = Date.parse(value)
    if (!Number.isFinite(ms)) return value
    return new Date(ms).toLocaleString()
  }

  function summarizeUA(ua: string): string {
    const raw = ua.trim()
    if (!raw) return 'Unknown client'
    if (raw.length <= 72) return raw
    return `${raw.slice(0, 69)}…`
  }

  async function loadSessions() {
    if (auth.tokenAuth) {
      sessions = []
      sessionsLoading = false
      sessionsError = ''
      return
    }
    sessionsLoading = true
    try {
      const res = await api.auth.sessions()
      sessions = res.sessions
      sessionsError = ''
    } catch (err) {
      sessionsError = err instanceof APIError ? err.message : 'failed to load sessions'
    } finally {
      sessionsLoading = false
    }
  }

  onMount(() => {
    username = auth.user?.username ?? ''
    void loadSessions()
  })

  async function saveUsername(event: SubmitEvent) {
    event.preventDefault()
    const next = username.trim()
    if (!next || next === auth.user?.username) return
    savingUser = true
    try {
      const res = await api.auth.updateProfile(next)
      auth.user = res.user
      toast.info('Username updated')
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to update username')
    } finally {
      savingUser = false
    }
  }

  async function savePassword(event: SubmitEvent) {
    event.preventDefault()
    if (newPassword !== confirmPassword) {
      toast.error('new passwords do not match')
      return
    }
    savingPass = true
    try {
      await api.auth.changePassword(currentPassword, newPassword)
      toast.info('Password updated. Sign in again.')
      currentPassword = ''
      newPassword = ''
      confirmPassword = ''
      await auth.logout()
      await goto(`${base}/login`)
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to update password')
    } finally {
      savingPass = false
    }
  }

  async function refreshSession() {
    refreshing = true
    try {
      const ok = await auth.refreshSession()
      if (ok) {
        toast.info('Session refreshed')
        await loadSessions()
      } else {
        toast.error('failed to refresh session')
      }
    } finally {
      refreshing = false
    }
  }

  async function afterSignedOut(message: string) {
    toast.info(message)
    auth.clearSession()
    await goto(`${base}/login`)
  }

  async function confirmDoRevoke() {
    if (!confirmRevoke) return
    const target = confirmRevoke
    confirmRevoke = null
    revoking = true
    try {
      const res = await api.auth.revokeSession(target.id)
      if (res.signed_out) {
        await afterSignedOut('Session ended')
        return
      }
      toast.info('Session revoked')
      await loadSessions()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to revoke session')
    } finally {
      revoking = false
    }
  }

  async function confirmDoRevokeAll() {
    confirmRevokeAll = false
    revoking = true
    try {
      const res = await api.auth.revokeAllSessions()
      if (res.signed_out) {
        await afterSignedOut('All sessions signed out')
        return
      }
      toast.info('Sessions revoked')
      await loadSessions()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to revoke sessions')
    } finally {
      revoking = false
    }
  }
</script>

<div class="page-head">
  <div class="page-head-text">
    <h1 class="page-title">Profile</h1>
    <p class="page-sub">Account details, password, and active sessions</p>
  </div>
</div>

<section class="config-section profile-hero">
  <div class="profile-identity">
    <div class="profile-avatar mono" aria-hidden="true">
      {(auth.user?.username ?? '?').slice(0, 1).toUpperCase()}
    </div>
    <div class="profile-identity-text">
      <div class="profile-name mono">{auth.user?.username ?? ''}</div>
      <div class="profile-meta">
        <span class="badge badge-{auth.role ?? 'viewer'}">{auth.role ?? ''}</span>
        {#if auth.tokenAuth}
          <span class="muted">API token auth</span>
        {:else}
          <span class="muted">Session expires {expiresLabel}</span>
        {/if}
      </div>
    </div>
  </div>
  {#if !auth.tokenAuth}
    <button type="button" class="btn btn-ghost" onclick={() => void refreshSession()} disabled={refreshing}>
      {refreshing ? 'Refreshing…' : 'Refresh session'}
    </button>
  {/if}
</section>

<section class="config-section settings-block">
  <h2 class="section-title">Username</h2>
  <p class="section-note muted">Changing your username does not sign out other sessions.</p>
  <form class="config-form" onsubmit={saveUsername}>
    <div class="field">
      <label for="profile-username">Username</label>
      <input
        id="profile-username"
        type="text"
        bind:value={username}
        autocomplete="username"
        required
        maxlength="64"
      />
    </div>
    <button
      type="submit"
      class="btn btn-primary"
      disabled={savingUser || username.trim() === (auth.user?.username ?? '')}
    >
      {savingUser ? 'Saving…' : 'Save username'}
    </button>
  </form>
</section>

<section class="config-section settings-block">
  <div class="section-head">
    <div>
      <h2 class="section-title">Sessions</h2>
      <p class="section-note muted">Revoke a device you no longer trust, or sign out everywhere.</p>
    </div>
    {#if !auth.tokenAuth}
      <button
        type="button"
        class="btn btn-sm btn-danger"
        disabled={revoking || sessionsLoading || sessions.length === 0}
        onclick={() => (confirmRevokeAll = true)}
      >
        Sign out all
      </button>
    {/if}
  </div>

  {#if auth.tokenAuth}
    <p class="alert">Session list is available when signed in with a browser cookie.</p>
  {:else if sessionsLoading}
    <p class="alert alert-loading">Loading sessions…</p>
  {:else if sessionsError}
    <p class="alert alert-error">{sessionsError}</p>
  {:else}
    <div class="table-wrap">
      <table class="session-table">
        <thead>
          <tr>
            <th>Client</th>
            <th>IP</th>
            <th>Created</th>
            <th>Expires</th>
            <th class="actions">Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each sessions as sess (sess.id)}
            <tr class:session-current={sess.current}>
              <td>
                <div class="session-client">
                  <span class="session-ua" title={sess.user_agent}>{summarizeUA(sess.user_agent)}</span>
                  {#if sess.current}
                    <span class="badge badge-ok">This device</span>
                  {/if}
                </div>
              </td>
              <td class="mono muted">{sess.ip || '—'}</td>
              <td class="muted">{formatWhen(sess.created_at)}</td>
              <td class="muted">{formatWhen(sess.expires_at)}</td>
              <td class="actions">
                <button
                  type="button"
                  class="btn btn-sm"
                  class:btn-danger={!sess.current}
                  class:btn-ghost={sess.current}
                  disabled={revoking}
                  onclick={() => (confirmRevoke = sess)}
                >
                  {sess.current ? 'Sign out' : 'Revoke'}
                </button>
              </td>
            </tr>
          {:else}
            <tr class="empty-row"><td colspan="5">No active sessions</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if otherSessionCount > 0}
      <p class="section-note muted">{otherSessionCount} other active session{otherSessionCount === 1 ? '' : 's'}.</p>
    {/if}
  {/if}
</section>

<section class="config-section settings-block">
  <h2 class="section-title">Password</h2>
  <p class="section-note muted">Changing your password signs out every session.</p>
  <form class="config-form" onsubmit={savePassword}>
    <div class="field">
      <label for="current-password">Current password</label>
      <input
        id="current-password"
        type="password"
        bind:value={currentPassword}
        autocomplete="current-password"
        required
      />
    </div>
    <div class="field">
      <label for="new-password">New password</label>
      <input
        id="new-password"
        type="password"
        bind:value={newPassword}
        autocomplete="new-password"
        required
        minlength="12"
      />
    </div>
    <div class="field">
      <label for="confirm-password">Confirm new password</label>
      <input
        id="confirm-password"
        type="password"
        bind:value={confirmPassword}
        autocomplete="new-password"
        required
        minlength="12"
      />
    </div>
    <button type="submit" class="btn btn-primary" disabled={savingPass}>
      {savingPass ? 'Updating…' : 'Change password'}
    </button>
  </form>
</section>

<ConfirmDialog
  open={confirmRevoke !== null}
  title={confirmRevoke?.current ? 'Sign out this device' : 'Revoke session'}
  message={confirmRevoke?.current
    ? 'End the session on this device and return to the login page?'
    : `Revoke the session from ${summarizeUA(confirmRevoke?.user_agent ?? '')} (${confirmRevoke?.ip || 'unknown IP'})?`}
  confirmLabel={confirmRevoke?.current ? 'Sign out' : 'Revoke'}
  danger
  onconfirm={confirmDoRevoke}
  oncancel={() => (confirmRevoke = null)}
/>

<ConfirmDialog
  open={confirmRevokeAll}
  title="Sign out all sessions"
  message="Revoke every active session for your account, including this device. You will need to sign in again."
  confirmLabel="Sign out all"
  danger
  onconfirm={confirmDoRevokeAll}
  oncancel={() => (confirmRevokeAll = false)}
/>
