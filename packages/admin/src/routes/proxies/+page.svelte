<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import { api, APIError, type ProxyNode } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canWriteConfig } from '$lib/rbac'
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte'
  import { Copy, RefreshCw } from '@lucide/svelte'

  let proxies = $state<ProxyNode[]>([])
  let hubURL = $state('')
  let hubPub = $state('')
  let loading = $state(true)
  let refreshing = $state(false)
  let error = $state('')
  let name = $state('')
  let publicIPv4 = $state('')
  let publicIPv6 = $state('')
  let submitting = $state(false)
  let busyID = $state<string | null>(null)
  let confirmDelete = $state<ProxyNode | null>(null)
  let confirmRotate = $state<ProxyNode | null>(null)
  let enroll = $state<{ name: string; token: string; hub_url: string; hub_pubkey: string } | null>(null)
  let lastPoll = $state('')

  const canWrite = $derived(canWriteConfig(auth.role))
  const onlineCount = $derived(proxies.filter((p) => p.online).length)

  let pollTimer: ReturnType<typeof setInterval> | undefined

  async function load(opts: { quiet?: boolean } = {}) {
    if (opts.quiet) refreshing = true
    else loading = true
    try {
      const res = await api.proxies.list()
      proxies = res.proxies ?? []
      hubURL = res.hub_url ?? ''
      hubPub = res.hub_pubkey ?? ''
      error = ''
      lastPoll = new Date().toLocaleTimeString()
    } catch (e) {
      const msg = e instanceof APIError ? e.message : 'failed to load proxies'
      if (opts.quiet) toast.warning(msg)
      else error = msg
    } finally {
      loading = false
      refreshing = false
    }
  }

  async function copyText(label: string, text: string) {
    if (!text) {
      toast.warning(`${label} is empty`)
      return
    }
    try {
      await navigator.clipboard.writeText(text)
      toast.success(`Copied ${label}`)
    } catch {
      toast.error(`Could not copy ${label}`)
    }
  }

  function agentTOML(e: { hub_url: string; token: string; hub_pubkey: string }) {
    return `[agent]
hub_url = "${e.hub_url}"
token = "${e.token}"
hub_pubkey = "${e.hub_pubkey}"
data_dir = "./data/proxy"`
  }

  async function createProxy(event: SubmitEvent) {
    event.preventDefault()
    if (!name.trim()) return
    submitting = true
    try {
      const res = await api.proxies.create({
        name: name.trim(),
        public_ipv4: publicIPv4.trim(),
        public_ipv6: publicIPv6.trim(),
      })
      enroll = {
        name: res.proxy.name,
        token: res.enrollment_token,
        hub_url: res.hub_url || hubURL,
        hub_pubkey: res.hub_pubkey || hubPub,
      }
      name = ''
      publicIPv4 = ''
      publicIPv6 = ''
      toast.success(`Enrolled ${res.proxy.name} · token shown once`)
      await load({ quiet: true })
    } catch (e) {
      toast.error(e instanceof APIError ? e.message : 'create failed')
    } finally {
      submitting = false
    }
  }

  async function push(p: ProxyNode) {
    if (!p.online) {
      toast.warning(`${p.name} is offline · cannot push`)
      return
    }
    busyID = p.id
    try {
      await api.proxies.push(p.id)
      toast.success(`Pushed desired state to ${p.name}`)
      await load({ quiet: true })
    } catch (e) {
      toast.error(e instanceof APIError ? e.message : 'push failed')
    } finally {
      busyID = null
    }
  }

  async function doRotate() {
    const p = confirmRotate
    confirmRotate = null
    if (!p) return
    busyID = p.id
    try {
      const res = await api.proxies.rotateToken(p.id)
      enroll = {
        name: res.proxy.name,
        token: res.enrollment_token,
        hub_url: res.hub_url || hubURL,
        hub_pubkey: res.hub_pubkey || hubPub,
      }
      toast.warning(`Token rotated for ${p.name} · reconfigure the agent`)
      await load({ quiet: true })
    } catch (e) {
      toast.error(e instanceof APIError ? e.message : 'rotate failed')
    } finally {
      busyID = null
    }
  }

  async function doDelete() {
    const p = confirmDelete
    confirmDelete = null
    if (!p) return
    busyID = p.id
    try {
      await api.proxies.remove(p.id)
      if (enroll?.name === p.name) enroll = null
      toast.success(`Removed ${p.name}`)
      await load({ quiet: true })
    } catch (e) {
      toast.error(e instanceof APIError ? e.message : 'delete failed')
    } finally {
      busyID = null
    }
  }

  function seenLabel(p: ProxyNode): string {
    if (!p.last_seen_at) return p.online ? 'connected' : 'never seen'
    const t = Date.parse(p.last_seen_at)
    if (Number.isNaN(t)) return p.last_seen_at
    const sec = Math.max(0, Math.round((Date.now() - t) / 1000))
    if (sec < 5) return 'just now'
    if (sec < 60) return `${sec}s ago`
    if (sec < 3600) return `${Math.floor(sec / 60)}m ago`
    if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`
    return `${Math.floor(sec / 86400)}d ago`
  }

  onMount(() => {
    void load()
    pollTimer = setInterval(() => void load({ quiet: true }), 8000)
  })

  onDestroy(() => {
    if (pollTimer) clearInterval(pollTimer)
  })
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Proxies</h1>
    <p class="page-sub">Enroll edge proxies that dial this hub over the overlay network</p>
  </div>
  <div class="actions-row">
    {#if lastPoll}
      <span class="muted poll-meta">Updated {lastPoll}</span>
    {/if}
    <button
      type="button"
      class="btn btn-ghost"
      onclick={() => load()}
      disabled={loading || refreshing}
    >
      <RefreshCw size={14} strokeWidth={1.75} aria-hidden="true" class={refreshing ? 'spin' : ''} />
      Refresh
    </button>
  </div>
</div>

{#if !loading && !error}
  <div class="metric-grid proxy-metrics">
    <div class="metric">
      <div class="metric-label">Proxies</div>
      <div class="metric-value">{proxies.length}</div>
    </div>
    <div class="metric">
      <div class="metric-label">Online</div>
      <div class="metric-value" class:ok={onlineCount > 0}>{onlineCount}</div>
      <div class="metric-note">{proxies.length ? `${proxies.length - onlineCount} offline` : 'none enrolled'}</div>
    </div>
    <div class="metric">
      <div class="metric-label">Hub URL</div>
      <div class="metric-value metric-compact mono">{hubURL || 'unset'}</div>
    </div>
  </div>
{/if}

{#if hubURL || hubPub}
  <div class="section">
    <div class="section-title">Hub identity</div>
    <div class="hub-grid">
      <div class="hub-row">
        <span class="hub-key">HUB_URL</span>
        <code class="mono hub-val">{hubURL || '(set hub.public_url)'}</code>
        <button type="button" class="btn btn-ghost btn-sm" disabled={!hubURL} onclick={() => copyText('HUB_URL', hubURL)}>
          <Copy size={14} strokeWidth={1.75} aria-hidden="true" />
          Copy
        </button>
      </div>
      <div class="hub-row">
        <span class="hub-key">HUB_PUBKEY</span>
        <code class="mono hub-val wrap">{hubPub || '—'}</code>
        <button type="button" class="btn btn-ghost btn-sm" disabled={!hubPub} onclick={() => copyText('HUB_PUBKEY', hubPub)}>
          <Copy size={14} strokeWidth={1.75} aria-hidden="true" />
          Copy
        </button>
      </div>
    </div>
  </div>
{/if}

{#if canWrite}
  <div class="section">
    <div class="section-title">Enroll proxy</div>
    <form class="field-row" onsubmit={createProxy}>
      <div class="field">
        <label for="proxy-name">Name</label>
        <input id="proxy-name" type="text" bind:value={name} required placeholder="edge-1" autocomplete="off" />
      </div>
      <div class="field">
        <label for="proxy-v4">Public IPv4</label>
        <input id="proxy-v4" type="text" bind:value={publicIPv4} placeholder="for DNS checklist" autocomplete="off" />
      </div>
      <div class="field">
        <label for="proxy-v6">Public IPv6</label>
        <input id="proxy-v6" type="text" bind:value={publicIPv6} placeholder="optional" autocomplete="off" />
      </div>
      <div class="field-btn">
        <button type="submit" class="btn btn-primary" disabled={submitting || !name.trim()}>
          {submitting ? 'Creating…' : 'Create'}
        </button>
      </div>
    </form>
  </div>
{/if}

{#if enroll}
  <div class="section enroll-panel" role="status">
    <div class="section-title">Agent install · {enroll.name}</div>
    <p class="alert enroll-alert">
      Enrollment token is shown once. Paste into the proxy TOML, then start the agent.
    </p>
    <pre class="mono enroll-pre">{agentTOML(enroll)}</pre>
    <div class="actions-row enroll-actions">
      <button type="button" class="btn btn-primary btn-sm" onclick={() => copyText('agent config', agentTOML(enroll!))}>
        <Copy size={14} strokeWidth={1.75} aria-hidden="true" />
        Copy TOML
      </button>
      <button type="button" class="btn btn-ghost btn-sm" onclick={() => copyText('token', enroll!.token)}>
        Copy token
      </button>
      <button type="button" class="btn btn-ghost btn-sm" onclick={() => (enroll = null)}>Dismiss</button>
    </div>
  </div>
{/if}

{#if loading}
  <p class="alert alert-loading">Loading proxies…</p>
{:else if error}
  <p class="alert alert-error">{error}</p>
{:else}
  <div class="section">
    <div class="section-title">Fleet</div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Status</th>
            <th>Seen</th>
            <th>Revision</th>
            <th>Public IP</th>
            <th>Host</th>
            <th>Version</th>
            {#if canWrite}<th class="actions">Actions</th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each proxies as p (p.id)}
            <tr>
              <td>
                <strong>{p.name}</strong>
                {#if p.universal}
                  <span class="badge">universal</span>
                {/if}
              </td>
              <td>
                <span class="status-pill">
                  <span class="dot" class:ok={p.online} class:bad={!p.online}></span>
                  <span class="badge" class:badge-ok={p.online}>{p.online ? 'online' : 'offline'}</span>
                </span>
              </td>
              <td class="muted">{seenLabel(p)}</td>
              <td class="mono">{p.desired_revision}</td>
              <td class="mono muted">
                {p.public_ipv4 || p.public_ipv6 || '—'}
              </td>
              <td class="muted cell-clip">{p.hostname || '—'}</td>
              <td class="mono muted">{p.agent_version || '—'}</td>
              {#if canWrite}
                <td class="actions">
                  <button
                    type="button"
                    class="btn btn-sm btn-primary"
                    disabled={busyID === p.id || !p.online}
                    title={p.online ? 'Push desired state' : 'Proxy offline'}
                    onclick={() => push(p)}
                  >
                    {busyID === p.id ? 'Working…' : 'Push'}
                  </button>
                  <button
                    type="button"
                    class="btn btn-sm btn-ghost"
                    disabled={busyID === p.id}
                    onclick={() => (confirmRotate = p)}
                  >
                    Rotate
                  </button>
                  <button
                    type="button"
                    class="btn btn-sm btn-danger"
                    disabled={busyID === p.id}
                    onclick={() => (confirmDelete = p)}
                  >
                    Delete
                  </button>
                </td>
              {/if}
            </tr>
          {:else}
            <tr class="empty-row">
              <td colspan={canWrite ? 8 : 7}>No proxies enrolled yet</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>
{/if}

<ConfirmDialog
  open={confirmDelete != null}
  title="Delete proxy"
  message={confirmDelete ? `Remove ${confirmDelete.name}? Agents using this enrollment will stop connecting.` : ''}
  confirmLabel="Delete"
  danger
  onconfirm={doDelete}
  oncancel={() => (confirmDelete = null)}
/>

<ConfirmDialog
  open={confirmRotate != null}
  title="Rotate enrollment token"
  message={confirmRotate
    ? `Issue a new token for ${confirmRotate.name}? The previous token stops working immediately.`
    : ''}
  confirmLabel="Rotate"
  danger
  onconfirm={doRotate}
  oncancel={() => (confirmRotate = null)}
/>

<style>
  .poll-meta {
    font-size: 0.78rem;
  }

  .proxy-metrics {
    margin-bottom: 1.75rem;
  }

  .metric-compact {
    font-size: 0.95rem;
    word-break: break-all;
  }

  .hub-grid {
    display: grid;
    gap: 0.65rem;
  }

  .hub-row {
    display: grid;
    grid-template-columns: 7.5rem 1fr auto;
    gap: 0.75rem;
    align-items: start;
    padding: 0.55rem 0;
    border-bottom: 1px solid var(--line);
  }

  .hub-key {
    font-family: var(--font-mono);
    font-size: 0.72rem;
    letter-spacing: 0.08em;
    color: var(--code);
    padding-top: 0.35rem;
  }

  .hub-val {
    font-size: 0.85rem;
    overflow-wrap: anywhere;
  }

  .wrap {
    word-break: break-all;
  }

  .enroll-panel {
    border: 1px solid color-mix(in srgb, var(--warn) 45%, var(--line));
    padding: 0 0 0.25rem;
  }

  .enroll-alert {
    border-left-color: var(--warn);
    margin-top: 0.5rem;
  }

  .enroll-pre {
    margin: 0.75rem 0;
    padding: 0.85rem 1rem;
    overflow: auto;
    border: 1px solid var(--line);
    background: color-mix(in srgb, var(--bg-raised) 80%, transparent);
    font-size: 0.8rem;
    line-height: 1.45;
  }

  .enroll-actions {
    justify-content: flex-start;
    margin-bottom: 0.5rem;
  }

  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
  }

  :global(.spin) {
    animation: spin 0.9s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  @media (max-width: 720px) {
    .hub-row {
      grid-template-columns: 1fr;
    }
  }
</style>
