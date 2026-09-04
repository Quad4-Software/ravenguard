<script lang="ts">
  import { onMount } from 'svelte'
  import { api, APIError, type ProxyNode, type Route, type ServiceMigration } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canWriteConfig } from '$lib/rbac'
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte'
  import { Copy, RefreshCw } from '@lucide/svelte'

  const phases = ['created', 'prepared', 'completed'] as const

  let proxies = $state<ProxyNode[]>([])
  let routes = $state<Route[]>([])
  let migrations = $state<ServiceMigration[]>([])
  let fromID = $state('')
  let toID = $state('')
  let selected = $state<string[]>([])
  let active = $state<ServiceMigration | null>(null)
  let loading = $state(true)
  let refreshing = $state(false)
  let busy = $state('')
  let confirmAbort = $state(false)
  let confirmComplete = $state(false)
  let dnsDone = $state(false)

  const canWrite = $derived(canWriteConfig(auth.role))
  const fromProxy = $derived(proxies.find((p) => p.id === fromID))
  const toProxy = $derived(proxies.find((p) => p.id === toID))
  const selectableRoutes = $derived(
    routes.filter((rt) => !fromID || !rt.proxy_id || rt.proxy_id === fromID),
  )
  const canStart = $derived(
    Boolean(fromID && toID && fromID !== toID && selected.length > 0 && !busy),
  )

  async function load(opts: { quiet?: boolean } = {}) {
    if (opts.quiet) refreshing = true
    else loading = true
    try {
      const [p, r, m] = await Promise.all([
        api.proxies.list(),
        api.routes.list(),
        api.migrations.list(),
      ])
      proxies = p.proxies ?? []
      routes = r.routes ?? []
      migrations = m.migrations ?? []
      if (active) {
        const fresh = migrations.find((x) => x.id === active?.id)
        if (fresh) active = fresh
      } else {
        active =
          migrations.find((x) => x.phase === 'created' || x.phase === 'prepared') ??
          migrations[0] ??
          null
      }
      if (active?.phase === 'prepared') {
        /* keep dnsDone user choice */
      } else {
        dnsDone = false
      }
    } catch (e) {
      toast.error(e instanceof APIError ? e.message : 'load failed')
    } finally {
      loading = false
      refreshing = false
    }
  }

  function toggle(id: string) {
    if (selected.includes(id)) selected = selected.filter((x) => x !== id)
    else selected = [...selected, id]
  }

  function selectAllVisible() {
    selected = selectableRoutes.map((r) => r.id)
  }

  function clearSelected() {
    selected = []
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

  async function create() {
    if (!canStart) return
    if (toProxy && !toProxy.online) {
      toast.warning(`${toProxy.name} is offline · prep will fail until it reconnects`)
    }
    busy = 'create'
    try {
      const res = await api.migrations.create({
        from_proxy_id: fromID,
        to_proxy_id: toID,
        route_ids: selected,
      })
      active = res.migration
      dnsDone = false
      toast.success('Migration created · prep the destination next')
      selected = []
      await load({ quiet: true })
    } catch (e) {
      toast.error(e instanceof APIError ? e.message : 'create failed')
    } finally {
      busy = ''
    }
  }

  async function prep() {
    if (!active) return
    busy = 'prep'
    try {
      const res = await api.migrations.prep(active.id)
      active = res.migration
      dnsDone = false
      toast.success('Destination prepared · update DNS, then complete')
      await load({ quiet: true })
    } catch (e) {
      toast.error(e instanceof APIError ? e.message : 'prep failed')
    } finally {
      busy = ''
    }
  }

  async function doComplete() {
    confirmComplete = false
    if (!active) return
    busy = 'complete'
    try {
      const res = await api.migrations.complete(active.id)
      active = res.migration
      toast.success('Cut over complete')
      await load({ quiet: true })
    } catch (e) {
      toast.error(e instanceof APIError ? e.message : 'complete failed')
    } finally {
      busy = ''
    }
  }

  async function doAbort() {
    confirmAbort = false
    if (!active) return
    busy = 'abort'
    try {
      const res = await api.migrations.abort(active.id)
      active = res.migration
      toast.info('Migration aborted')
      await load({ quiet: true })
    } catch (e) {
      toast.error(e instanceof APIError ? e.message : 'abort failed')
    } finally {
      busy = ''
    }
  }

  function proxyName(id: string) {
    return proxies.find((p) => p.id === id)?.name ?? id.slice(0, 8)
  }

  function proxyOnline(id: string) {
    return Boolean(proxies.find((p) => p.id === id)?.online)
  }

  function phaseIndex(phase: string): number {
    if (phase === 'aborted') return -1
    const i = phases.indexOf(phase as (typeof phases)[number])
    return i >= 0 ? i : 0
  }

  function phaseBadge(phase: string): string {
    if (phase === 'completed') return 'badge badge-ok'
    if (phase === 'prepared') return 'badge badge-admin'
    if (phase === 'aborted') return 'badge'
    return 'badge badge-owner'
  }

  function openMigration(m: ServiceMigration) {
    active = m
    dnsDone = m.phase === 'prepared' ? dnsDone : false
  }

  onMount(() => {
    void load()
  })
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Move services</h1>
    <p class="page-sub">Stage routes on another proxy, update DNS, then cut over</p>
  </div>
  <button type="button" class="btn btn-ghost" onclick={() => load()} disabled={loading || refreshing}>
    <RefreshCw size={14} strokeWidth={1.75} aria-hidden="true" class={refreshing ? 'spin' : ''} />
    Refresh
  </button>
</div>

{#if loading}
  <p class="alert alert-loading">Loading migrations…</p>
{:else}
  {#if canWrite}
    <div class="section">
      <div class="section-title">Start migration</div>
      <div class="wizard-form">
        <div class="field-row">
          <div class="field">
            <label for="mig-from">From proxy</label>
            <select id="mig-from" bind:value={fromID}>
              <option value="">Select…</option>
              {#each proxies as p (p.id)}
                <option value={p.id}>{p.name}{p.online ? '' : ' (offline)'}</option>
              {/each}
            </select>
            {#if fromID}
              <span class="field-hint">
                <span class="dot" class:ok={fromProxy?.online} class:bad={!fromProxy?.online}></span>
                {fromProxy?.online ? 'online' : 'offline'}
              </span>
            {/if}
          </div>
          <div class="field">
            <label for="mig-to">To proxy</label>
            <select id="mig-to" bind:value={toID}>
              <option value="">Select…</option>
              {#each proxies as p (p.id)}
                <option value={p.id} disabled={p.id === fromID}>
                  {p.name}{p.online ? '' : ' (offline)'}
                </option>
              {/each}
            </select>
            {#if toID}
              <span class="field-hint">
                <span class="dot" class:ok={toProxy?.online} class:bad={!toProxy?.online}></span>
                {toProxy?.online ? 'online' : 'offline'}
                {#if toProxy && !toProxy.online}
                  · prep needs this agent connected
                {/if}
              </span>
            {/if}
          </div>
        </div>

        <fieldset class="route-pick">
          <legend>Routes to move</legend>
          <div class="route-pick-bar">
            <span class="muted">{selected.length} selected</span>
            <button type="button" class="btn btn-ghost btn-sm" onclick={selectAllVisible} disabled={!selectableRoutes.length}>
              Select all
            </button>
            <button type="button" class="btn btn-ghost btn-sm" onclick={clearSelected} disabled={!selected.length}>
              Clear
            </button>
          </div>
          {#if selectableRoutes.length === 0}
            <p class="muted">No routes match the source proxy.</p>
          {:else}
            <ul class="route-list">
              {#each selectableRoutes as rt (rt.id)}
                <li>
                  <label class="check">
                    <input
                      type="checkbox"
                      checked={selected.includes(rt.id)}
                      onchange={() => toggle(rt.id)}
                    />
                    <span>
                      <strong>{rt.name}</strong>
                      <span class="muted">
                        · {(rt.hosts ?? []).join(', ') || '*'}
                        · {rt.proxy_id ? proxyName(rt.proxy_id) : 'unassigned'}
                      </span>
                    </span>
                  </label>
                </li>
              {/each}
            </ul>
          {/if}
        </fieldset>

        <button type="button" class="btn btn-primary" disabled={!canStart} onclick={create}>
          {busy === 'create' ? 'Starting…' : 'Start migration'}
        </button>
      </div>
    </div>
  {/if}

  {#if active}
    <div class="section active-panel">
      <div class="section-title">
        Active · {proxyName(active.from_proxy_id)} → {proxyName(active.to_proxy_id)}
      </div>

      <ol class="steps" aria-label="Migration phases">
        {#each phases as step, i (step)}
          {@const idx = phaseIndex(active.phase)}
          {@const done = idx > i || active.phase === 'completed'}
          {@const current = idx === i && active.phase !== 'aborted'}
          <li class="step" class:done class:current class:aborted={active.phase === 'aborted' && i === 0}>
            <span class="step-mark">{done ? 'ok' : i + 1}</span>
            <span class="step-label">{step}</span>
          </li>
        {/each}
        {#if active.phase === 'aborted'}
          <li class="step aborted current">
            <span class="step-mark">!</span>
            <span class="step-label">aborted</span>
          </li>
        {/if}
      </ol>

      <p class="phase-line">
        <span class={phaseBadge(active.phase)}>{active.phase}</span>
        <span class="muted">
          destination
          <span class="dot inline-dot" class:ok={proxyOnline(active.to_proxy_id)} class:bad={!proxyOnline(active.to_proxy_id)}
          ></span>
          {proxyOnline(active.to_proxy_id) ? 'online' : 'offline'}
        </span>
      </p>

      {#if active.detail}
        <p class="alert">{active.detail}</p>
      {/if}

      {#if active.dns_checklist?.length && (active.phase === 'prepared' || active.phase === 'completed')}
        <div class="dns-block">
          <h3 class="dns-title">DNS checklist</h3>
          <p class="alert dns-banner">
            Traffic follows DNS. Point records at the destination public IP, wait for propagation, then complete.
          </p>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Suggested A</th>
                  <th>Suggested AAAA</th>
                  <th>Was</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {#each active.dns_checklist as item (item.host)}
                  <tr>
                    <td class="mono">{item.host}</td>
                    <td class="mono">{item.suggested_a || '—'}</td>
                    <td class="mono">{item.suggested_aaaa || '—'}</td>
                    <td class="muted mono">{item.from_ipv4 || item.from_ipv6 || '—'}</td>
                    <td class="actions">
                      {#if item.suggested_a}
                        <button
                          type="button"
                          class="btn btn-ghost btn-sm"
                          onclick={() => copyText(`${item.host} A`, item.suggested_a ?? '')}
                        >
                          <Copy size={14} strokeWidth={1.75} aria-hidden="true" />
                          A
                        </button>
                      {/if}
                      {#if item.suggested_aaaa}
                        <button
                          type="button"
                          class="btn btn-ghost btn-sm"
                          onclick={() => copyText(`${item.host} AAAA`, item.suggested_aaaa ?? '')}
                        >
                          <Copy size={14} strokeWidth={1.75} aria-hidden="true" />
                          AAAA
                        </button>
                      {/if}
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          {#if active.phase === 'prepared' && canWrite}
            <label class="check dns-confirm">
              <input type="checkbox" bind:checked={dnsDone} />
              I updated DNS and waited for propagation
            </label>
          {/if}
        </div>
      {/if}

      {#if canWrite && active.phase !== 'completed'}
        <div class="actions-row mig-actions">
          {#if active.phase === 'created' || active.phase === 'aborted'}
            <button
              type="button"
              class="btn btn-primary"
              disabled={busy !== '' || !proxyOnline(active.to_proxy_id)}
              title={proxyOnline(active.to_proxy_id) ? 'Copy routes and certs to destination' : 'Destination offline'}
              onclick={prep}
            >
              {busy === 'prep' ? 'Preparing…' : 'Prep destination'}
            </button>
          {/if}
          {#if active.phase === 'prepared'}
            <button
              type="button"
              class="btn btn-primary"
              disabled={busy !== '' || !dnsDone}
              onclick={() => (confirmComplete = true)}
            >
              {busy === 'complete' ? 'Completing…' : 'Complete cutover'}
            </button>
          {/if}
          <button
            type="button"
            class="btn btn-danger"
            disabled={busy !== ''}
            onclick={() => (confirmAbort = true)}
          >
            Abort
          </button>
        </div>
      {/if}
    </div>
  {/if}

  <div class="section">
    <div class="section-title">History</div>
    {#if migrations.length === 0}
      <p class="muted">No migrations yet.</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Move</th>
              <th>Phase</th>
              <th>Routes</th>
              <th>Updated</th>
            </tr>
          </thead>
          <tbody>
            {#each migrations as m (m.id)}
              <tr class:row-active={active?.id === m.id}>
                <td>
                  <button type="button" class="btn btn-ghost btn-sm" onclick={() => openMigration(m)}>
                    {proxyName(m.from_proxy_id)} → {proxyName(m.to_proxy_id)}
                  </button>
                </td>
                <td><span class={phaseBadge(m.phase)}>{m.phase}</span></td>
                <td class="muted">{(m.route_ids ?? []).length}</td>
                <td class="muted mono">{m.updated_at ? new Date(m.updated_at).toLocaleString() : '—'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
{/if}

<ConfirmDialog
  open={confirmComplete}
  title="Complete cutover"
  message="Mark this migration complete? Source routes will stop serving these hosts after cutover."
  confirmLabel="Complete"
  onconfirm={doComplete}
  oncancel={() => (confirmComplete = false)}
/>

<ConfirmDialog
  open={confirmAbort}
  title="Abort migration"
  message="Abort this migration? Destination staging will be left for you to clean up if needed."
  confirmLabel="Abort"
  danger
  onconfirm={doAbort}
  oncancel={() => (confirmAbort = false)}
/>

<style>
  .wizard-form {
    display: grid;
    gap: 1rem;
    max-width: 44rem;
  }

  .field-hint {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    margin-top: 0.35rem;
    font-size: 0.78rem;
    color: var(--muted);
  }

  .route-pick {
    border: 1px solid var(--line);
    padding: 0.75rem 1rem 0.5rem;
  }

  .route-pick legend {
    font-family: var(--font-mono);
    font-size: 0.72rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--code);
    padding: 0 0.35rem;
  }

  .route-pick-bar {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    margin-bottom: 0.5rem;
  }

  .route-list {
    list-style: none;
    margin: 0;
    padding: 0;
    max-height: 14rem;
    overflow: auto;
  }

  .route-list li {
    padding: 0.35rem 0;
    border-bottom: 1px solid color-mix(in srgb, var(--line) 70%, transparent);
  }

  .check {
    display: flex;
    gap: 0.55rem;
    align-items: flex-start;
    cursor: pointer;
  }

  .steps {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    list-style: none;
    margin: 0 0 1rem;
    padding: 0;
  }

  .step {
    display: inline-flex;
    align-items: center;
    gap: 0.45rem;
    opacity: 0.45;
  }

  .step.done,
  .step.current {
    opacity: 1;
  }

  .step-mark {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 1.35rem;
    height: 1.35rem;
    border-radius: 50%;
    border: 1px solid var(--line);
    font-size: 0.72rem;
    font-family: var(--font-mono);
  }

  .step.done .step-mark {
    border-color: var(--ok);
    color: var(--ok);
  }

  .step.current .step-mark {
    border-color: var(--accent);
    color: var(--fg);
  }

  .step.aborted .step-mark {
    border-color: var(--bad);
    color: var(--bad);
  }

  .step-label {
    font-family: var(--font-mono);
    font-size: 0.72rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  .phase-line {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    align-items: center;
    margin-bottom: 0.85rem;
  }

  .inline-dot {
    margin: 0 0.2rem 0 0.35rem;
  }

  .dns-title {
    font-size: 0.95rem;
    font-weight: 500;
    margin: 0.5rem 0 0.65rem;
  }

  .dns-banner {
    border-left-color: var(--warn);
  }

  .dns-confirm {
    margin: 0.85rem 0 0.25rem;
    align-items: center;
  }

  .mig-actions {
    justify-content: flex-start;
    margin-top: 1rem;
  }

  .row-active td {
    background: color-mix(in srgb, var(--bg-raised) 70%, transparent);
  }

  .active-panel {
    padding-bottom: 0.25rem;
  }

  :global(.spin) {
    animation: spin 0.9s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
