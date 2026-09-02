<script lang="ts">
  import { onMount } from 'svelte'
  import { api, APIError, type Upstream } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canWriteConfig } from '$lib/rbac'
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte'

  let upstreams = $state<Upstream[]>([])
  let loading = $state(true)
  let error = $state('')
  let name = $state('')
  let url = $state('')
  let healthEnabled = $state(true)
  let submitting = $state(false)
  let saving = $state(false)
  let confirmDelete = $state<Upstream | null>(null)
  let editing = $state<Upstream | null>(null)

  let editName = $state('')
  let editUrl = $state('')
  let editConnectTimeout = $state('')
  let editResponseHeaderTimeout = $state('')
  let editIdleConnTimeout = $state('')
  let editMaxIdleConns = $state('')
  let editMaxIdleConnsPerHost = $state('')
  let editHealthEnabled = $state(true)
  let editHealthPath = $state('')
  let editHealthInterval = $state('')
  let editHealthTimeout = $state('')
  let editSetHeaders = $state('')

  const canWrite = $derived(canWriteConfig(auth.role))

  function optionalInt(value: string): number | undefined {
    const t = value.trim()
    if (!t) return undefined
    const n = Number(t)
    return Number.isFinite(n) ? n : undefined
  }

  function optionalText(value: string): string | undefined {
    const t = value.trim()
    return t ? t : undefined
  }

  function parseHeaders(text: string): string[] {
    return text
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
  }

  function startEdit(up: Upstream) {
    editing = up
    editName = up.name
    editUrl = up.url
    editConnectTimeout = up.connect_timeout ?? ''
    editResponseHeaderTimeout = up.response_header_timeout ?? ''
    editIdleConnTimeout = up.idle_conn_timeout ?? ''
    editMaxIdleConns = up.max_idle_conns != null && up.max_idle_conns !== 0 ? String(up.max_idle_conns) : ''
    editMaxIdleConnsPerHost =
      up.max_idle_conns_per_host != null && up.max_idle_conns_per_host !== 0 ? String(up.max_idle_conns_per_host) : ''
    editHealthEnabled = up.health_enabled
    editHealthPath = up.health_path ?? ''
    editHealthInterval = up.health_interval ?? ''
    editHealthTimeout = up.health_timeout ?? ''
    editSetHeaders = (up.set_headers ?? []).join('\n')
  }

  function cancelEdit() {
    editing = null
  }

  async function load() {
    loading = true
    try {
      const res = await api.upstreams.list()
      upstreams = res.upstreams ?? []
      error = ''
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load upstreams'
    } finally {
      loading = false
    }
  }

  async function createUpstream(event: SubmitEvent) {
    event.preventDefault()
    const n = name.trim()
    const u = url.trim()
    if (!n || !u) return
    submitting = true
    try {
      await api.upstreams.create({
        name: n,
        url: u,
        health_enabled: healthEnabled,
      })
      toast.info(`Upstream ${n} created`)
      name = ''
      url = ''
      healthEnabled = true
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to create upstream')
    } finally {
      submitting = false
    }
  }

  async function saveEdit(event: SubmitEvent) {
    event.preventDefault()
    if (!editing) return
    const n = editName.trim()
    const u = editUrl.trim()
    if (!n || !u) return
    saving = true
    try {
      await api.upstreams.update(editing.id, {
        name: n,
        url: u,
        connect_timeout: optionalText(editConnectTimeout),
        response_header_timeout: optionalText(editResponseHeaderTimeout),
        idle_conn_timeout: optionalText(editIdleConnTimeout),
        max_idle_conns: optionalInt(editMaxIdleConns),
        max_idle_conns_per_host: optionalInt(editMaxIdleConnsPerHost),
        max_conns_per_host: editing.max_conns_per_host,
        flush_interval: editing.flush_interval,
        health_enabled: editHealthEnabled,
        health_path: optionalText(editHealthPath),
        health_interval: optionalText(editHealthInterval),
        health_timeout: optionalText(editHealthTimeout),
        set_headers: parseHeaders(editSetHeaders),
      })
      toast.info(`Upstream ${n} updated`)
      editing = null
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to update upstream')
    } finally {
      saving = false
    }
  }

  async function confirmRemove() {
    if (!confirmDelete) return
    const up = confirmDelete
    confirmDelete = null
    try {
      await api.upstreams.remove(up.id)
      toast.info(`Removed ${up.name}`)
      if (editing?.id === up.id) editing = null
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to remove upstream')
    }
  }

  onMount(load)
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Upstreams</h1>
    <p class="page-sub">Backend targets for routed traffic</p>
  </div>
</div>

{#if canWrite && editing}
  <fieldset>
    <legend>Edit upstream</legend>
    <form onsubmit={saveEdit}>
      <div class="field-row">
        <div class="field">
          <label for="up-edit-name">Name</label>
          <input id="up-edit-name" type="text" bind:value={editName} required />
        </div>
        <div class="field">
          <label for="up-edit-url">URL</label>
          <input id="up-edit-url" type="text" bind:value={editUrl} required />
        </div>
        <div class="field">
          <label for="up-edit-connect">Connect timeout</label>
          <input id="up-edit-connect" type="text" bind:value={editConnectTimeout} placeholder="5s" />
        </div>
        <div class="field">
          <label for="up-edit-resp">Response header timeout</label>
          <input id="up-edit-resp" type="text" bind:value={editResponseHeaderTimeout} placeholder="30s" />
        </div>
        <div class="field">
          <label for="up-edit-idle">Idle conn timeout</label>
          <input id="up-edit-idle" type="text" bind:value={editIdleConnTimeout} placeholder="90s" />
        </div>
        <div class="field">
          <label for="up-edit-max-idle">Max idle conns</label>
          <input id="up-edit-max-idle" type="text" inputmode="numeric" bind:value={editMaxIdleConns} />
        </div>
        <div class="field">
          <label for="up-edit-max-idle-host">Max idle conns per host</label>
          <input id="up-edit-max-idle-host" type="text" inputmode="numeric" bind:value={editMaxIdleConnsPerHost} />
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="up-edit-health-enabled">
            <input id="up-edit-health-enabled" type="checkbox" bind:checked={editHealthEnabled} />
            Health checks
          </label>
        </div>
        <div class="field">
          <label for="up-edit-health-path">Health path</label>
          <input id="up-edit-health-path" type="text" bind:value={editHealthPath} placeholder="/healthz" />
        </div>
        <div class="field">
          <label for="up-edit-health-interval">Health interval</label>
          <input id="up-edit-health-interval" type="text" bind:value={editHealthInterval} placeholder="10s" />
        </div>
        <div class="field">
          <label for="up-edit-health-timeout">Health timeout</label>
          <input id="up-edit-health-timeout" type="text" bind:value={editHealthTimeout} placeholder="3s" />
        </div>
      </div>
      <div class="field">
        <label for="up-edit-headers">Set headers</label>
        <textarea
          id="up-edit-headers"
          bind:value={editSetHeaders}
          placeholder="Name: value"
          rows="4"
        ></textarea>
        <p class="field-help">One header per line as Name: value</p>
      </div>
      <div class="field-row">
        <div class="field-btn">
          <button type="submit" class="btn btn-primary" disabled={saving || !editName.trim() || !editUrl.trim()}>
            {saving ? 'Saving…' : 'Save upstream'}
          </button>
        </div>
        <div class="field-btn">
          <button type="button" class="btn" onclick={cancelEdit}>Cancel</button>
        </div>
      </div>
    </form>
  </fieldset>
{:else if canWrite}
  <fieldset>
    <legend>Add upstream</legend>
    <form class="field-row" onsubmit={createUpstream}>
      <div class="field">
        <label for="up-name">Name</label>
        <input id="up-name" type="text" bind:value={name} required />
      </div>
      <div class="field">
        <label for="up-url">URL</label>
        <input id="up-url" type="text" bind:value={url} placeholder="http://127.0.0.1:8080" required />
      </div>
      <div class="field">
        <label for="up-health">
          <input id="up-health" type="checkbox" bind:checked={healthEnabled} />
          Health checks
        </label>
      </div>
      <div class="field-btn">
        <button type="submit" class="btn btn-primary" disabled={submitting || !name.trim() || !url.trim()}>
          {submitting ? 'Creating…' : 'Create upstream'}
        </button>
      </div>
    </form>
  </fieldset>
{/if}

{#if loading}
  <p class="alert alert-loading">Loading upstreams…</p>
{:else if error}
  <p class="alert alert-error">{error}</p>
{:else}
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>URL</th>
        <th>Health</th>
        {#if canWrite}<th class="actions">Actions</th>{/if}
      </tr>
    </thead>
    <tbody>
      {#each upstreams as up (up.id)}
        <tr>
          <td>{up.name}</td>
          <td class="mono">{up.url}</td>
          <td class="muted">{up.health_enabled ? 'enabled' : 'off'}</td>
          {#if canWrite}
            <td class="actions">
              <div class="actions-row">
                <button type="button" class="btn btn-sm" onclick={() => startEdit(up)}>Edit</button>
                <button type="button" class="btn btn-sm btn-danger" onclick={() => (confirmDelete = up)}>
                  Delete
                </button>
              </div>
            </td>
          {/if}
        </tr>
      {:else}
        <tr class="empty-row"><td colspan={canWrite ? 4 : 3}>No upstreams</td></tr>
      {/each}
    </tbody>
  </table>
{/if}

<ConfirmDialog
  open={confirmDelete !== null}
  title="Delete upstream"
  message={`Remove upstream "${confirmDelete?.name}"?`}
  confirmLabel="Delete"
  danger
  onconfirm={confirmRemove}
  oncancel={() => (confirmDelete = null)}
/>
