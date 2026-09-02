<script lang="ts">
  import { onMount } from 'svelte'
  import { api, APIError, type Ban } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canWriteOps } from '$lib/rbac'
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte'

  let bans = $state<Ban[]>([])
  let loading = $state(true)
  let error = $state('')
  let newKey = $state('')
  let submitting = $state(false)
  let confirmKey = $state<string | null>(null)

  const canWrite = $derived(canWriteOps(auth.role))

  async function load() {
    loading = true
    try {
      const res = await api.bans.list()
      bans = res.bans ?? []
      error = ''
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load bans'
    } finally {
      loading = false
    }
  }

  async function addBan(event: SubmitEvent) {
    event.preventDefault()
    const key = newKey.trim()
    if (!key) return
    submitting = true
    try {
      await api.bans.create(key)
      toast.info(`Banned ${key}`)
      newKey = ''
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to ban key')
    } finally {
      submitting = false
    }
  }

  async function confirmUnban() {
    if (!confirmKey) return
    const key = confirmKey
    confirmKey = null
    try {
      await api.bans.remove(key)
      toast.info(`Unbanned ${key}`)
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to unban key')
    }
  }

  onMount(load)
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Bans</h1>
    <p class="page-sub">Active bans enforced by the guard</p>
  </div>
</div>

{#if canWrite}
  <form class="field-row" onsubmit={addBan}>
    <div class="field">
      <label for="ban-key">Ban key</label>
      <input id="ban-key" type="text" bind:value={newKey} placeholder="ip, client id, or fingerprint" />
    </div>
    <div class="field-btn">
      <button type="submit" class="btn btn-primary" disabled={submitting || !newKey.trim()}>
        {submitting ? 'Adding…' : 'Add ban'}
      </button>
    </div>
  </form>
{/if}

{#if loading}
  <p class="alert alert-loading">Loading bans…</p>
{:else if error}
  <p class="alert alert-error">{error}</p>
{:else}
  <table>
    <thead>
      <tr>
        <th>Key</th>
        <th>Strikes</th>
        <th>Banned until</th>
        <th>Active</th>
        {#if canWrite}<th class="actions">Actions</th>{/if}
      </tr>
    </thead>
    <tbody>
      {#each bans as ban (ban.key)}
        <tr>
          <td class="mono">{ban.key}</td>
          <td class="mono">{ban.strikes}</td>
          <td class="muted">{ban.banned_until || '—'}</td>
          <td class="muted">{ban.active ? 'yes' : 'no'}</td>
          {#if canWrite}
            <td class="actions">
              <button type="button" class="btn btn-sm btn-danger" onclick={() => (confirmKey = ban.key)}>
                Unban
              </button>
            </td>
          {/if}
        </tr>
      {:else}
        <tr class="empty-row"><td colspan={canWrite ? 5 : 4}>No active bans</td></tr>
      {/each}
    </tbody>
  </table>
{/if}

<ConfirmDialog
  open={confirmKey !== null}
  title="Unban key"
  message={`Remove the ban for "${confirmKey}"?`}
  confirmLabel="Unban"
  danger
  onconfirm={confirmUnban}
  oncancel={() => (confirmKey = null)}
/>
