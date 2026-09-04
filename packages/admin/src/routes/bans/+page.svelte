<script lang="ts">
  import { onMount } from 'svelte'
  import { api, APIError, type Ban } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canWriteOps } from '$lib/rbac'
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte'

  type ThreatRow = {
    id: string
    key_type: string
    key_redacted: string
    ttl_deadline: string
    reason: string
    source_proxy_id: string
    revision: number
    created_at: string
  }

  let bans = $state<Ban[]>([])
  let threats = $state<ThreatRow[]>([])
  let threatRev = $state(0)
  let loading = $state(true)
  let error = $state('')
  let newKey = $state('')
  let shareKey = $state('')
  let shareType = $state('bind')
  let shareReason = $state('')
  let submitting = $state(false)
  let confirmKey = $state<string | null>(null)

  const canWrite = $derived(canWriteOps(auth.role))

  async function load() {
    loading = true
    try {
      const [banRes, threatRes] = await Promise.all([api.bans.list(), api.threat.list(50)])
      bans = banRes.bans ?? []
      threats = threatRes.entries ?? []
      threatRev = threatRes.revision ?? 0
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

  async function shareThreat(event: SubmitEvent) {
    event.preventDefault()
    const key = shareKey.trim()
    if (!key) return
    submitting = true
    try {
      await api.threat.create({
        key_type: shareType,
        key,
        reason: shareReason.trim() || 'admin share',
        ttl: '10m',
      })
      toast.info('Shared to fleet')
      shareKey = ''
      shareReason = ''
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to share threat')
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
    <p class="page-sub">Local bans and fleet-shared threat entries</p>
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

  <h2 class="section-title">Fleet threat share</h2>
  <p class="page-sub">Revision {threatRev}. Keys are redacted. Shared bans apply on all online proxies.</p>

  {#if canWrite}
    <form class="field-row" onsubmit={shareThreat}>
      <div class="field">
        <label for="share-type">Type</label>
        <select id="share-type" bind:value={shareType}>
          <option value="bind">bind</option>
          <option value="ua">ua</option>
          <option value="ip">ip</option>
          <option value="ja4">ja4</option>
        </select>
      </div>
      <div class="field">
        <label for="share-key">Key</label>
        <input id="share-key" type="text" bind:value={shareKey} placeholder="bind hash, UA needle, or IP" />
      </div>
      <div class="field">
        <label for="share-reason">Reason</label>
        <input id="share-reason" type="text" bind:value={shareReason} placeholder="scraper" />
      </div>
      <div class="field-btn">
        <button type="submit" class="btn btn-primary" disabled={submitting || !shareKey.trim()}>
          Share
        </button>
      </div>
    </form>
  {/if}

  <table>
    <thead>
      <tr>
        <th>Type</th>
        <th>Key</th>
        <th>Reason</th>
        <th>Source</th>
        <th>Expires</th>
      </tr>
    </thead>
    <tbody>
      {#each threats as row (row.id)}
        <tr>
          <td class="mono">{row.key_type}</td>
          <td class="mono">{row.key_redacted}</td>
          <td class="muted">{row.reason || '—'}</td>
          <td class="mono muted">{row.source_proxy_id || '—'}</td>
          <td class="muted">{row.ttl_deadline}</td>
        </tr>
      {:else}
        <tr class="empty-row"><td colspan="5">No shared threat entries</td></tr>
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
