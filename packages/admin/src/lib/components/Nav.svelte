<script lang="ts">
  import { page } from '$app/state'
  import { base } from '$app/paths'
  import { goto } from '$app/navigation'
  import { auth } from '$lib/auth.svelte'
  import { toast } from '$lib/toast.svelte'
  import { canManageUsers } from '$lib/rbac'
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

  interface NavLink {
    href: string
    label: string
    show: boolean
    icon: Component<IconProps>
  }

  const links = $derived<NavLink[]>([
    { href: `${base}/`, label: 'Overview', show: true, icon: LayoutDashboard },
    { href: `${base}/proxies`, label: 'Proxies', show: true, icon: Network },
    { href: `${base}/migrations`, label: 'Move services', show: true, icon: ArrowRightLeft },
    { href: `${base}/upstreams`, label: 'Upstreams', show: true, icon: Server },
    { href: `${base}/routes`, label: 'Routes', show: true, icon: Waypoints },
    { href: `${base}/access`, label: 'Access', show: true, icon: KeyRound },
    { href: `${base}/certs`, label: 'Certificates', show: true, icon: BadgeCheck },
    { href: `${base}/logs`, label: 'Logs', show: true, icon: ScrollText },
    { href: `${base}/bans`, label: 'Bans', show: true, icon: Ban },
    { href: `${base}/blocklists`, label: 'Blocklists', show: true, icon: ListX },
    { href: `${base}/qfeeds`, label: 'Q-Feeds', show: true, icon: Rss },
    { href: `${base}/appearance`, label: 'Appearance', show: true, icon: Palette },
    { href: `${base}/config`, label: 'Config', show: true, icon: SlidersHorizontal },
    { href: `${base}/users`, label: 'Users', show: canManageUsers(auth.role), icon: Users },
    { href: `${base}/tokens`, label: 'Tokens', show: true, icon: Key },
    { href: `${base}/audit`, label: 'Audit', show: true, icon: ClipboardList },
  ])

  function isActive(href: string): boolean {
    const path: string = page.url.pathname
    if (href === `${base}/`) return path === `${base}/` || path === base
    return path === href || path.startsWith(`${href}/`)
  }

  async function handleLogout() {
    await auth.logout()
    toast.info('Signed out')
    await goto(`${base}/login`)
  }
</script>

<aside class="shell-nav">
  <div class="brand">
    <div class="brand-name">RavenGuard</div>
    <div class="brand-sub">Admin Console</div>
  </div>
  <nav class="nav-scroll" aria-label="Admin">
    <ul class="nav-list">
      {#each links as link (link.href)}
        {#if link.show}
          {@const Icon = link.icon}
          <li class="nav-item">
            <a class="nav-link" class:active={isActive(link.href)} href={link.href}>
              <Icon class="nav-link-icon" size={17} strokeWidth={1.75} aria-hidden="true" />
              {link.label}
            </a>
          </li>
        {/if}
      {/each}
    </ul>
  </nav>
  <div class="nav-foot">
    <a class="user-row nav-link" href={`${base}/settings`} class:active={isActive(`${base}/settings`)}>
      <span class="username mono">{auth.user?.username ?? ''}</span>
      <span class="badge badge-{auth.role ?? 'viewer'}">{auth.role ?? ''}</span>
    </a>
    <button type="button" class="btn btn-ghost btn-sm nav-signout" onclick={handleLogout}>
      Sign out
    </button>
  </div>
</aside>
