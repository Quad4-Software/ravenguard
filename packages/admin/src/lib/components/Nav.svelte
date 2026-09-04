<script lang="ts">
  import { onMount } from 'svelte'
  import { page } from '$app/state'
  import { base } from '$app/paths'
  import { goto } from '$app/navigation'
  import { api } from '$lib/api'
  import { auth } from '$lib/auth.svelte'
  import { toast } from '$lib/toast.svelte'
  import {
    NAV_LINK_SPECS,
    joinBasePath,
    isNavActive,
    navLinkVisible,
  } from '$lib/nav'
  import { shell } from '$lib/shell.svelte'
  import type { Component } from 'svelte'
  import type { IconProps } from '@lucide/svelte'
  import {
    LayoutDashboard,
    Server,
    Waypoints,
    KeyRound,
    BadgeCheck,
    ScrollText,
    Ban,
    ListX,
    Rss,
    Palette,
    SlidersHorizontal,
    Users,
    Key,
    ClipboardList,
    Network,
    ArrowRightLeft,
  } from '@lucide/svelte'

  const NAV_ICONS: Record<string, Component<IconProps>> = {
    '/': LayoutDashboard,
    '/proxies': Network,
    '/migrations': ArrowRightLeft,
    '/upstreams': Server,
    '/routes': Waypoints,
    '/access': KeyRound,
    '/certs': BadgeCheck,
    '/logs': ScrollText,
    '/bans': Ban,
    '/blocklists': ListX,
    '/qfeeds': Rss,
    '/appearance': Palette,
    '/config': SlidersHorizontal,
    '/users': Users,
    '/tokens': Key,
    '/audit': ClipboardList,
  }

  let hubVersion = $state('')
  let hubCommit = $state('')

  const versionLabel = $derived.by(() => {
    const short = hubCommit.trim().slice(0, 7)
    if (!short) return ''
    const v = hubVersion.trim()
    if (!v || v === 'dev') return `ver ${short}`
    return `ver ${v} ${short}`
  })

  const links = $derived(
    NAV_LINK_SPECS.map((spec) => ({
      href: joinBasePath(base, spec.path),
      label: spec.label,
      show: navLinkVisible(spec, auth.role),
      icon: NAV_ICONS[spec.path],
    })),
  )

  const settingsHref = $derived(joinBasePath(base, '/settings'))

  onMount(() => {
    void api.status
      .get()
      .then((s) => {
        hubVersion = s.version ?? ''
        hubCommit = s.commit ?? ''
      })
      .catch(() => {})
  })

  async function handleLogout() {
    shell.closeNav()
    await auth.logout()
    toast.info('Signed out')
    await goto(`${base}/login`)
  }
</script>

<aside id="admin-nav" class="shell-nav">
  <div class="brand">
    <div class="brand-name">RavenGuard</div>
    <div class="brand-sub">Admin Console</div>
    {#if versionLabel}
      <div class="nav-version">{versionLabel}</div>
    {/if}
  </div>
  <nav class="nav-scroll" aria-label="Admin">
    <ul class="nav-list">
      {#each links as link (link.href)}
        {#if link.show}
          {@const Icon = link.icon}
          <li class="nav-item">
            <a
              class="nav-link"
              class:active={isNavActive(page.url.pathname, link.href, base)}
              href={link.href}
              onclick={() => shell.closeNav()}
            >
              <Icon class="nav-link-icon" size={18} strokeWidth={1.75} aria-hidden="true" />
              {link.label}
            </a>
          </li>
        {/if}
      {/each}
    </ul>
  </nav>
  <div class="nav-foot">
    <a
      class="user-row nav-link"
      href={settingsHref}
      class:active={isNavActive(page.url.pathname, settingsHref, base)}
      onclick={() => shell.closeNav()}
    >
      <span class="username mono">{auth.user?.username ?? ''}</span>
      <span class="badge badge-{auth.role ?? 'viewer'}">{auth.role ?? ''}</span>
    </a>
    <button type="button" class="btn btn-ghost btn-sm nav-signout" onclick={handleLogout}>
      Sign out
    </button>
  </div>
</aside>

<style>
  .nav-version {
    font-family: var(--font-mono);
    font-size: 0.65rem;
    letter-spacing: 0.04em;
    color: var(--muted);
    margin-top: 0.35rem;
  }
</style>
