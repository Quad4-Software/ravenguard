<script lang="ts">
  import { onMount } from 'svelte'
  import { api, APIError, type BlocklistStats } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canWriteOps } from '$lib/rbac'
  import Metric from '$lib/components/Metric.svelte'

  type Kind = 'ip' | 'dns' | 'ua'

  let stats = $state<BlocklistStats | null>(null)
  let kind = $state<Kind>('ip')
  let entries = $state<string[]>([])
  let filter = $state('')
  let newValue = $state('')
  let editFrom = $state('')
  let editTo = $state('')
  let loading = $state(true)
  let error = $state('')
  let busy = $state(false)

  const canWrite = $derived(canWriteOps(auth.role))

  const filtered = $derived(
    filter.trim()
      ? entries.filter((e) => e.toLowerCase().includes(filter.trim().toLowerCase()))
      : entries,
  )

  async function loadAll() {
    loading = true
    try {
      const [st, list] = await Promise.all([api.blocklists.stats(), api.blocklists.entries(kind)])
      stats = st
      entries = list.entries ?? []
      error = ''
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load blocklists'
    } finally {
      loading = false
    }
  }

  async function switchKind(next: Kind) {
    kind = next
    editFrom = ''
    editTo = ''
    try {
      const list = await api.blocklists.entries(kind)
      entries = list.entries ?? []
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to load entries')
    }
  }

  async function reload() {
    busy = true
    try {
      stats = await api.blocklists.reload()
      const list = await api.blocklists.entries(kind)
      entries = list.entries ?? []
      toast.info('Blocklists reloaded')
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'reload failed')
    } finally {
      busy = false
    }
  }

  async function addEntry(event: SubmitEvent) {
    event.preventDefault()
    if (!newValue.trim()) return
    busy = true
    try {
      const res = await api.blocklists.add(kind, newValue.trim())
      entries = res.entries ?? []
      stats = res.stats
      newValue = ''
      toast.info('Entry added')
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'add failed')
    } finally {
      busy = false
    }
  }

  async function removeEntry(value: string) {
    busy = true
    try {
      const res = await api.blocklists.remove(kind, value)
      entries = res.entries ?? []
      stats = res.stats
      if (editFrom === value) {
        editFrom = ''
        editTo = ''
      }
      toast.info('Entry removed')
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'remove failed')
    } finally {
      busy = false
    }
  }

  async function saveEdit(event: SubmitEvent) {
    event.preventDefault()
    if (!editFrom || !editTo.trim()) return
    busy = true
    try {
      const res = await api.blocklists.edit(kind, editFrom, editTo.trim())
      entries = res.entries ?? []
      stats = res.stats
      editFrom = ''
      editTo = ''
      toast.info('Entry updated')
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'edit failed')
    } finally {
      busy = false
    }
  }

  function startEdit(value: string) {
    editFrom = value
    editTo = value
  }

  onMount(loadAll)
</script>

<div class="page-head">
  <div class="page-head-text">
    <h1 class="page-title">Blocklists</h1>
    <p class="page-sub">Add, edit, or remove IP, DNS, and user-agent entries</p>
  </div>
  {#if canWrite}
    <button type="button" class="btn btn-primary" onclick={reload} disabled={busy}>
      {busy ? 'Working…' : 'Reload now'}
    </button>
  {/if}
</div>

{#if loading}
  <p class="alert alert-loading">Loading…</p>
{:else if error}
  <p class="alert alert-error">{error}</p>
{:else if stats}
  <div class="metric-grid">
    <Metric label="IP entries" value={String(stats.ip_count)} />
    <Metric label="DNS entries" value={String(stats.dns_count)} />
    <Metric label="UA entries" value={String(stats.ua_count)} />
    <Metric label="Last reload" value={stats.last_reload ? new Date(stats.last_reload).toLocaleString() : 'never'} />
  </div>

  {#if stats.overlay_dir}
    <p class="muted mono wrap-text section-note">Overlay: {stats.overlay_dir}</p>
  {/if}

  <div class="section">
    <div class="tab-row" role="tablist">
      {#each ['ip', 'dns', 'ua'] as k (k)}
        <button
          type="button"
          class="tab"
          class:active={kind === k}
          role="tab"
          aria-selected={kind === k}
          onclick={() => switchKind(k as Kind)}
        >
          {k.toUpperCase()}
        </button>
      {/each}
    </div>

    <div class="field">
      <label for="bl-filter">Filter</label>
      <input id="bl-filter" type="search" bind:value={filter} placeholder="Filter entries…" />
    </div>

    {#if canWrite}
      <form class="field-row" onsubmit={addEntry}>
        <div class="field">
          <label for="bl-add">Add {kind} entry</label>
          <input id="bl-add" type="text" bind:value={newValue} placeholder={kind === 'ip' ? '1.2.3.4 or CIDR' : 'value'} />
        </div>
        <div class="field-btn">
          <button type="submit" class="btn btn-primary" disabled={busy || !newValue.trim()}>Add</button>
        </div>
      </form>

      {#if editFrom}
        <form class="field-row" onsubmit={saveEdit}>
          <div class="field">
            <label for="bl-edit">Edit entry</label>
            <input id="bl-edit" type="text" bind:value={editTo} />
          </div>
          <div class="field-btn actions-row">
            <button type="submit" class="btn btn-primary" disabled={busy || !editTo.trim()}>Save</button>
            <button type="button" class="btn" onclick={() => { editFrom = ''; editTo = '' }}>Cancel</button>
          </div>
        </form>
      {/if}
    {/if}

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Entry</th>
            {#if canWrite}
              <th class="actions">Actions</th>
            {/if}
          </tr>
        </thead>
        <tbody>
          {#each filtered as entry (entry)}
            <tr>
              <td class="mono cell-clip">{entry}</td>
              {#if canWrite}
                <td class="actions">
                  <div class="actions-row">
                    <button type="button" class="btn btn-sm" onclick={() => startEdit(entry)} disabled={busy}>Edit</button>
                    <button type="button" class="btn btn-sm btn-danger" onclick={() => removeEntry(entry)} disabled={busy}
                      >Remove</button
                    >
                  </div>
                </td>
              {/if}
            </tr>
          {:else}
            <tr class="empty-row">
              <td colspan={canWrite ? 2 : 1}>No entries</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>
{/if}
