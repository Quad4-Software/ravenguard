<script lang="ts">
  import { onMount, onDestroy } from 'svelte'
  import { api, APIError, type LogEntry } from '$lib/api'

  let logs = $state<LogEntry[]>([])
  let loading = $state(true)
  let error = $state('')
  let level = $state('')
  let limit = $state(200)
  let auto = $state(true)
  let filter = $state('')
  let timer: ReturnType<typeof setInterval> | undefined

  const filtered = $derived(
    logs.filter((e) => {
      if (!filter.trim()) return true
      const q = filter.toLowerCase()
      if (e.message.toLowerCase().includes(q)) return true
      if (e.level.toLowerCase().includes(q)) return true
      if (e.attrs) {
        return Object.values(e.attrs).some((v) => String(v).toLowerCase().includes(q))
      }
      return false
    }),
  )

  async function load() {
    if (typeof document !== 'undefined' && document.hidden) return
    try {
      const res = await api.logs.list(limit, level)
      logs = res.logs ?? []
      error = ''
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load logs'
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

  function levelClass(lv: string): string {
    switch (lv.toLowerCase()) {
      case 'error':
        return 'badge badge-owner'
      case 'warn':
      case 'warning':
        return 'badge badge-admin'
      case 'debug':
        return 'muted'
      default:
        return 'badge badge-viewer'
    }
  }

  function handleVisibility() {
    if (!document.hidden && auto) load()
  }

  onMount(() => {
    load()
    timer = setInterval(() => {
      if (auto) load()
    }, 3000)
    document.addEventListener('visibilitychange', handleVisibility)
  })

  onDestroy(() => {
    if (timer) clearInterval(timer)
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', handleVisibility)
    }
  })
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Logs</h1>
    <p class="page-sub">Recent process log lines from the in-memory ring buffer</p>
  </div>
  <button type="button" class="btn btn-ghost" onclick={load} disabled={loading}>Refresh</button>
</div>

<div class="field-row">
  <div class="field">
    <label for="log-level">Min level</label>
    <select id="log-level" bind:value={level} onchange={load}>
      <option value="">all</option>
      <option value="debug">debug</option>
      <option value="info">info</option>
      <option value="warn">warn</option>
      <option value="error">error</option>
    </select>
  </div>
  <div class="field">
    <label for="log-limit">Limit</label>
    <input id="log-limit" type="number" min="20" max="2000" bind:value={limit} onchange={load} />
  </div>
  <div class="field">
    <label for="log-filter">Filter</label>
    <input id="log-filter" type="text" bind:value={filter} placeholder="search message or attrs" />
  </div>
  <div class="field checkbox-field">
    <input id="log-auto" type="checkbox" bind:checked={auto} />
    <label for="log-auto">Auto-refresh</label>
  </div>
</div>

{#if loading && logs.length === 0}
  <p class="alert alert-loading">Loading logs…</p>
{:else if error}
  <p class="alert alert-error">{error}</p>
{:else}
  <div class="table-wrap log-table">
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Level</th>
          <th>Message</th>
          <th>Attrs</th>
        </tr>
      </thead>
      <tbody>
        {#each filtered as entry, i (`${entry.time}-${i}`)}
          <tr>
            <td class="mono muted">{formatTime(entry.time)}</td>
            <td><span class={levelClass(entry.level)}>{entry.level}</span></td>
            <td class="mono cell-wrap">{entry.message}</td>
            <td class="mono muted cell-wrap">
              {#if entry.attrs}
                {Object.entries(entry.attrs)
                  .map(([k, v]) => `${k}=${v}`)
                  .join(' ')}
              {:else}
                —
              {/if}
            </td>
          </tr>
        {:else}
          <tr class="empty-row"><td colspan="4">No log lines</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

<style>
  .log-table {
    max-height: 70vh;
    overflow: auto;
  }
</style>
