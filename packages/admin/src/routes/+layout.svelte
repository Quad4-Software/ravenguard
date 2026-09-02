<script lang="ts">
  import '../app.css'
  import { onMount } from 'svelte'
  import { page } from '$app/state'
  import { goto } from '$app/navigation'
  import { base } from '$app/paths'
  import { auth } from '$lib/auth.svelte'
  import Nav from '$lib/components/Nav.svelte'
  import Toast from '$lib/components/Toast.svelte'

  let { children } = $props()

  const loginPath = `${base}/login`

  onMount(() => {
    auth.restore()
  })

  $effect(() => {
    if (!auth.ready) return
    const onLogin = page.url.pathname === loginPath
    if (!auth.loggedIn && !onLogin) {
      goto(loginPath)
    } else if (auth.loggedIn && onLogin) {
      goto(`${base}/`)
    }
  })

  const showShell = $derived(auth.ready && auth.loggedIn && page.url.pathname !== loginPath)
</script>

{#if !auth.ready}
  <div class="login-wrap">
    <p class="muted mono pulse">Loading…</p>
  </div>
{:else if showShell}
  <div class="shell">
    <Nav />
    <main class="shell-main">
      {#key page.url.pathname}
        <div class="page-fade">
          {@render children()}
        </div>
      {/key}
    </main>
  </div>
{:else}
  {@render children()}
{/if}

<Toast />
