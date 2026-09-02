<script lang="ts">
  import { goto } from '$app/navigation'
  import { base } from '$app/paths'
  import { auth } from '$lib/auth.svelte'
  import { APIError } from '$lib/api'

  let username = $state('')
  let password = $state('')
  let error = $state('')

  async function handleSubmit(event: SubmitEvent) {
    event.preventDefault()
    error = ''
    try {
      await auth.login(username, password)
      await goto(`${base}/`)
    } catch (err) {
      error = err instanceof APIError ? err.message : 'login failed'
    }
  }
</script>

<div class="login-wrap">
  <main class="login-main">
    <img class="login-logo" src="{base}/raven.png" width="72" height="72" alt="" />
    <p class="code-label">Admin</p>
    <h1 class="login-brand">RavenGuard</h1>
    <p class="login-sub">Sign in to the control plane</p>

    {#if error}
      <p class="alert alert-error" role="alert">{error}</p>
    {/if}

    <form class="login-form" onsubmit={handleSubmit}>
      <div class="field">
        <label for="username">Username</label>
        <input
          id="username"
          name="username"
          type="text"
          autocomplete="username"
          bind:value={username}
          required
        />
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          autocomplete="current-password"
          bind:value={password}
          required
        />
      </div>
      <button type="submit" class="btn btn-primary" disabled={auth.pending}>
        {auth.pending ? 'Signing in…' : 'Sign in'}
      </button>
    </form>
  </main>
</div>
