<script lang="ts">
  import { onMount } from 'svelte'
  import { auth } from '$lib/auth.svelte'
  import { api, APIError } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { goto } from '$app/navigation'
  import { base } from '$app/paths'

  let username = $state('')
  let currentPassword = $state('')
  let newPassword = $state('')
  let confirmPassword = $state('')
  let savingUser = $state(false)
  let savingPass = $state(false)

  onMount(() => {
    username = auth.user?.username ?? ''
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
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Settings</h1>
    <p class="page-sub">Your profile and password</p>
  </div>
</div>

<section class="config-section">
  <h2 class="section-title">Profile</h2>
  <p class="page-sub settings-role">Role: <span class="mono">{auth.role}</span></p>
  <form class="config-form" onsubmit={saveUsername}>
    <div class="field">
      <label for="profile-username">Username</label>
      <input id="profile-username" type="text" bind:value={username} autocomplete="username" required maxlength="64" />
    </div>
    <button type="submit" class="btn btn-primary" disabled={savingUser || username.trim() === (auth.user?.username ?? '')}>
      {savingUser ? 'Saving…' : 'Save username'}
    </button>
  </form>
</section>

<section class="config-section settings-block">
  <h2 class="section-title">Password</h2>
  <form class="config-form" onsubmit={savePassword}>
    <div class="field">
      <label for="current-password">Current password</label>
      <input id="current-password" type="password" bind:value={currentPassword} autocomplete="current-password" required />
    </div>
    <div class="field">
      <label for="new-password">New password</label>
      <input id="new-password" type="password" bind:value={newPassword} autocomplete="new-password" required minlength="12" />
    </div>
    <div class="field">
      <label for="confirm-password">Confirm new password</label>
      <input id="confirm-password" type="password" bind:value={confirmPassword} autocomplete="new-password" required minlength="12" />
    </div>
    <button type="submit" class="btn btn-primary" disabled={savingPass}>
      {savingPass ? 'Updating…' : 'Change password'}
    </button>
  </form>
</section>
