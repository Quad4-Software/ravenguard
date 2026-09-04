<script lang="ts">
  import '../app.css'
  import { onMount } from 'svelte'
  import { page } from '$app/state'
  import { goto } from '$app/navigation'
  import { base } from '$app/paths'
  import { MediaQuery } from 'svelte/reactivity'
  import { auth } from '$lib/auth.svelte'
  import { SHELL_MOBILE_MAX_PX } from '$lib/shell'
  import { shell } from '$lib/shell.svelte'
  import Nav from '$lib/components/Nav.svelte'
  import Toast from '$lib/components/Toast.svelte'
  import { Menu, X } from '@lucide/svelte'

  let { children } = $props()

  const loginPath = `${base}/login`
  const desktop = new MediaQuery(`min-width: ${SHELL_MOBILE_MAX_PX + 1}px`)

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

  $effect(() => {
    if (desktop.current) shell.closeNav()
  })

  $effect(() => {
    if (typeof document === 'undefined') return
    document.body.style.overflow = shell.navOpen && !desktop.current ? 'hidden' : ''
  })

  const showShell = $derived(auth.ready && auth.loggedIn && page.url.pathname !== loginPath)

  function onWindowKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') shell.closeNav()
  }
</script>

<svelte:window onkeydown={onWindowKeydown} />

{#if !auth.ready}
  <div class="login-wrap">
    <p class="muted mono pulse">Loading…</p>
  </div>
{:else if showShell}
  <div class="shell" class:nav-open={shell.navOpen}>
    <header class="shell-top">
      <button
        type="button"
        class="shell-menu-btn"
        aria-label={shell.navOpen ? 'Close menu' : 'Open menu'}
        aria-expanded={shell.navOpen}
        aria-controls="admin-nav"
        onclick={() => shell.toggleNav()}
      >
        {#if shell.navOpen}
          <X size={20} aria-hidden="true" />
        {:else}
          <Menu size={20} aria-hidden="true" />
        {/if}
      </button>
      <div class="shell-top-brand">
        <div class="brand-name">RavenGuard</div>
      </div>
    </header>
    <button
      type="button"
      class="shell-backdrop"
      aria-label="Close menu"
      tabindex={shell.navOpen ? 0 : -1}
      onclick={() => shell.closeNav()}
    ></button>
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
