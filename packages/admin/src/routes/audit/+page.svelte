<script lang="ts">
  import { onMount } from 'svelte'
  import { api, APIError, type AuditEvent } from '$lib/api'

  const pageSize = 50

  let events = $state<AuditEvent[]>([])
  let loading = $state(true)
  let loadingMore = $state(false)
  let error = $state('')
  let done = $state(false)

  async function fetchPage(cursor?: number) {
    const res = await api.audit.list(cursor, pageSize)
    events = cursor ? [...events, ...res.events] : res.events
    if (res.events.length < pageSize) done = true
  }

  async function load() {
    loading = true
    try {
      await fetchPage()
      error = ''
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load audit log'
    } finally {
      loading = false
    }
  }

  async function loadMore() {
    if (events.length === 0) return
    loadingMore = true
    try {
      await fetchPage(events[events.length - 1].id)
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load more events'
    } finally {
      loadingMore = false
    }
  }

  onMount(load)
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Audit</h1>
    <p class="page-sub">Administrative action history</p>
  </div>
</div>

{#if loading}
  <p class="alert alert-loading">Loading audit log…</p>
{:else if error}
  <p class="alert alert-error">{error}</p>
{:else}
  <table>
    <thead>
      <tr>
        <th>Time</th>
        <th>Actor</th>
        <th>Action</th>
        <th>Target</th>
        <th>Detail</th>
        <th>IP</th>
      </tr>
    </thead>
    <tbody>
      {#each events as event (event.id)}
        <tr>
          <td class="mono muted">{event.created_at}</td>
          <td>{event.actor_name}</td>
          <td class="mono">{event.action}</td>
          <td>{event.target}</td>
          <td class="muted">{event.detail}</td>
          <td class="mono muted">{event.ip}</td>
        </tr>
      {:else}
        <tr class="empty-row"><td colspan="6">No audit events</td></tr>
      {/each}
    </tbody>
  </table>

  {#if !done && events.length > 0}
    <div class="section">
      <button type="button" class="btn" onclick={loadMore} disabled={loadingMore}>
        {loadingMore ? 'Loading…' : 'Load more'}
      </button>
    </div>
  {/if}
{/if}
