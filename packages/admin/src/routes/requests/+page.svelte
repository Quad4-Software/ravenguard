<script lang="ts">
  import { onMount } from 'svelte'
  import { api, APIError, type ProxyNode, type WAFEvent } from '$lib/api'
  import { toast } from '$lib/toast.svelte'

  type MLSample = {
    id: number
    ray: string
    label: string
    prob: number
    path: string
    method: string
  }

  let ray = $state('')
  let proxyId = $state('')
  let proxies = $state<ProxyNode[]>([])
  let event = $state<WAFEvent | null>(null)
  let recent = $state<WAFEvent[]>([])
  let loading = $state(false)
  let error = $state('')
  let mlSamples = $state<MLSample[]>([])
  let mlLoading = $state(false)
  let mlBusy = $state(false)

  async function loadProxies() {
    try {
      const res = await api.proxies.list()
      proxies = res.proxies ?? []
    } catch {
      proxies = []
    }
  }

  async function loadRecent() {
    try {
      const res = await api.requests.list(50, proxyId)
      recent = res.events ?? []
    } catch {
      recent = []
    }
  }

  async function loadMLSamples() {
    mlLoading = true
    try {
      const res = await api.ml.samples(50, true)
      mlSamples = res.samples ?? []
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to load ML samples')
    } finally {
      mlLoading = false
    }
  }

  async function labelSample(id: number, label: 'fp' | 'tp' | 'ignore') {
    mlBusy = true
    try {
      await api.ml.label(id, label)
      mlSamples = mlSamples.filter((s) => s.id !== id)
      toast.info(`Labeled sample ${id} as ${label}`)
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to label sample')
    } finally {
      mlBusy = false
    }
  }

  async function adaptModel() {
    mlBusy = true
    try {
      const res = await api.ml.adapt()
      toast.info(`Adapted model (${res.samples} samples, hash ${res.hash.slice(0, 12)}…)`)
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'adapt failed')
    } finally {
      mlBusy = false
    }
  }

  async function lookup(targetRay?: string) {
    const q = (targetRay ?? ray).trim()
    if (!q) {
      error = 'Enter a Ray ID'
      return
    }
    loading = true
    error = ''
    event = null
    try {
      const res = await api.requests.get(q, proxyId)
      event = res.event
      ray = q
    } catch (err) {
      error = err instanceof APIError ? err.message : 'lookup failed'
    } finally {
      loading = false
    }
  }

  function formatTime(t: string): string {
    try {
      return new Date(t).toLocaleString()
    } catch {
      return t
    }
  }

  function selectRecent(e: WAFEvent) {
    ray = e.ray
    void lookup(e.ray)
  }

  onMount(() => {
    void loadProxies()
    void loadRecent()
  })
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Requests</h1>
    <p class="page-sub">Look up WAF deny and challenge outcomes by Ray ID</p>
  </div>
  <button type="button" class="btn btn-ghost" onclick={() => loadRecent()}>Refresh recent</button>
</div>

<div class="card stack">
  <div class="field-row">
    <div class="field grow">
      <label for="ray-id">Ray ID</label>
      <input
        id="ray-id"
        type="text"
        bind:value={ray}
        placeholder="Paste X-RavenGuard-Ray value"
        onkeydown={(e) => {
          if (e.key === 'Enter') void lookup()
        }}
      />
    </div>
    {#if proxies.length > 0}
      <div class="field">
        <label for="proxy-id">Proxy</label>
        <select id="proxy-id" bind:value={proxyId} onchange={() => loadRecent()}>
          <option value="">local</option>
          {#each proxies as p (p.id)}
            <option value={p.id}>{p.name || p.id}</option>
          {/each}
        </select>
      </div>
    {/if}
    <div class="field field-action">
      <label for="lookup-btn">&nbsp;</label>
      <button id="lookup-btn" type="button" class="btn" onclick={() => lookup()} disabled={loading}>
        {loading ? 'Looking up…' : 'Look up'}
      </button>
    </div>
  </div>
  {#if error}
    <p class="error">{error}</p>
  {/if}
</div>

{#if event}
  <div class="card stack">
    <h2 class="section-title">Event</h2>
    <dl class="detail-grid">
      <dt>Ray</dt>
      <dd class="mono">{event.ray}</dd>
      <dt>Action</dt>
      <dd>{event.action}</dd>
      <dt>Reason</dt>
      <dd>{event.reason}</dd>
      <dt>When</dt>
      <dd>{formatTime(event.created_at)}</dd>
      <dt>Method</dt>
      <dd>{event.method || '—'}</dd>
      <dt>Path</dt>
      <dd class="mono">{event.path || '—'}</dd>
      <dt>Host</dt>
      <dd>{event.host || '—'}</dd>
      <dt>User-Agent</dt>
      <dd class="mono wrap">{event.ua || '—'}</dd>
      <dt>IP (log)</dt>
      <dd class="mono">{event.ip_hash || '—'}</dd>
      <dt>Bind ID</dt>
      <dd class="mono">{event.bind_id || '—'}</dd>
      <dt>Score</dt>
      <dd>{event.score}</dd>
    </dl>
    {#if event.details && Object.keys(event.details).length > 0}
      <h3 class="section-title">Details</h3>
      <dl class="detail-grid">
        {#each Object.entries(event.details) as [k, v] (k)}
          <dt>{k}</dt>
          <dd class="mono wrap">{v}</dd>
        {/each}
      </dl>
    {/if}
  </div>
{/if}

<div class="card stack">
  <h2 class="section-title">Recent denials</h2>
  {#if recent.length === 0}
    <p class="muted">No recent WAF events</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Action</th>
            <th>Reason</th>
            <th>Path</th>
            <th>Ray</th>
          </tr>
        </thead>
        <tbody>
          {#each recent as e (e.ray + e.created_at)}
            <tr>
              <td>{formatTime(e.created_at)}</td>
              <td>{e.action}</td>
              <td>{e.reason}</td>
              <td class="mono">{e.method} {e.path}</td>
              <td>
                <button type="button" class="linkish mono" onclick={() => selectRecent(e)}>{e.ray.slice(0, 16)}…</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<div class="card stack">
  <div class="ml-head">
    <h2 class="section-title">ML samples</h2>
    <div class="actions-row">
      <button type="button" class="btn btn-ghost" onclick={() => loadMLSamples()} disabled={mlLoading || mlBusy}>
        {mlLoading ? 'Loading…' : 'Load unlabeled'}
      </button>
      <button type="button" class="btn" onclick={() => adaptModel()} disabled={mlBusy || mlLoading}>
        Train adapt
      </button>
    </div>
  </div>
  {#if mlSamples.length === 0}
    <p class="muted">No unlabeled samples loaded</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Method</th>
            <th>Path</th>
            <th>Prob</th>
            <th>Ray</th>
            <th>Label</th>
          </tr>
        </thead>
        <tbody>
          {#each mlSamples as s (s.id)}
            <tr>
              <td>{s.id}</td>
              <td>{s.method}</td>
              <td class="mono">{s.path}</td>
              <td>{s.prob.toFixed(3)}</td>
              <td class="mono">{s.ray ? s.ray.slice(0, 16) + '…' : '—'}</td>
              <td>
                <div class="label-actions">
                  <button type="button" class="btn btn-ghost" disabled={mlBusy} onclick={() => labelSample(s.id, 'fp')}>
                    FP
                  </button>
                  <button type="button" class="btn btn-ghost" disabled={mlBusy} onclick={() => labelSample(s.id, 'tp')}>
                    TP
                  </button>
                  <button
                    type="button"
                    class="btn btn-ghost"
                    disabled={mlBusy}
                    onclick={() => labelSample(s.id, 'ignore')}
                  >
                    Ignore
                  </button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<style>
  .grow {
    flex: 1;
    min-width: 12rem;
  }
  .field-action {
    align-self: end;
  }
  .detail-grid {
    display: grid;
    grid-template-columns: 8rem 1fr;
    gap: 0.4rem 1rem;
    margin: 0;
  }
  .detail-grid dt {
    color: var(--muted, #888);
    font-size: 0.85rem;
  }
  .detail-grid dd {
    margin: 0;
    word-break: break-word;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.85rem;
  }
  .wrap {
    white-space: pre-wrap;
  }
  .linkish {
    background: none;
    border: none;
    color: inherit;
    text-decoration: underline;
    cursor: pointer;
    padding: 0;
  }
  .table-wrap {
    overflow-x: auto;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
  }
  th,
  td {
    text-align: left;
    padding: 0.4rem 0.5rem;
    border-bottom: 1px solid var(--border, #333);
  }
  .section-title {
    margin: 0;
    font-size: 1rem;
  }
  .stack {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }
  .ml-head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
  }
  .actions-row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }
  .label-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem;
  }
</style>
