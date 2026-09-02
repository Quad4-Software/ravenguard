<script lang="ts">
  import { onMount } from 'svelte'
  import { api, APIError, type AccessPolicy } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canWriteConfig } from '$lib/rbac'
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte'
  import AccessRuleList from '$lib/components/AccessRuleList.svelte'
  import { draftFromRule, draftsToRules, emptyDraft, type DraftRule } from '$lib/access-rules'

  let policies = $state<AccessPolicy[]>([])
  let loading = $state(true)
  let error = $state('')
  let name = $state('')
  let mode = $state<'all' | 'any'>('all')
  let cookieTtl = $state('24h')
  let createRules = $state<DraftRule[]>([emptyDraft()])
  let submitting = $state(false)
  let saving = $state(false)
  let confirmDelete = $state<AccessPolicy | null>(null)
  let editing = $state<AccessPolicy | null>(null)

  let editName = $state('')
  let editMode = $state<'all' | 'any'>('all')
  let editCookieTtl = $state('24h')
  let editRules = $state<DraftRule[]>([])

  const canWrite = $derived(canWriteConfig(auth.role))
  const createPayload = $derived(draftsToRules(createRules, false))
  const editPayload = $derived(draftsToRules(editRules, true))
  const canCreate = $derived(!!name.trim() && createPayload !== null && createPayload.length > 0)
  const canSave = $derived(!!editName.trim() && editPayload !== null && editPayload.length > 0)

  function startEdit(p: AccessPolicy) {
    editing = p
    editName = p.name
    editMode = p.mode === 'any' ? 'any' : 'all'
    editCookieTtl = p.cookie_ttl || '24h'
    const existing = (p.rules ?? []).map(draftFromRule)
    editRules = existing.length > 0 ? existing : [emptyDraft()]
  }

  function cancelEdit() {
    editing = null
    editRules = []
  }

  function resetCreate() {
    name = ''
    mode = 'all'
    cookieTtl = '24h'
    createRules = [emptyDraft()]
  }

  async function load() {
    loading = true
    try {
      const res = await api.accessPolicies.list()
      policies = res.access_policies ?? []
      error = ''
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load access policies'
    } finally {
      loading = false
    }
  }

  async function createPolicy(event: SubmitEvent) {
    event.preventDefault()
    const n = name.trim()
    const rules = createPayload
    if (!n || !rules || rules.length === 0) return
    submitting = true
    try {
      await api.accessPolicies.create({
        name: n,
        mode,
        rules,
        cookie_ttl: cookieTtl.trim() || '24h',
      })
      toast.info(`Policy ${n} created`)
      resetCreate()
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to create policy')
    } finally {
      submitting = false
    }
  }

  async function saveEdit(event: SubmitEvent) {
    event.preventDefault()
    if (!editing) return
    const n = editName.trim()
    const rules = editPayload
    if (!n || !rules || rules.length === 0) return
    saving = true
    try {
      await api.accessPolicies.update(editing.id, {
        name: n,
        mode: editMode,
        cookie_ttl: editCookieTtl.trim() || '24h',
        rules,
      })
      toast.info(`Policy ${n} updated`)
      cancelEdit()
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to update policy')
    } finally {
      saving = false
    }
  }

  async function confirmRemove() {
    if (!confirmDelete) return
    const p = confirmDelete
    confirmDelete = null
    try {
      await api.accessPolicies.remove(p.id)
      toast.info(`Removed ${p.name}`)
      if (editing?.id === p.id) cancelEdit()
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to remove policy')
    }
  }

  onMount(load)
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Access</h1>
    <p class="page-sub">Gate policies for protected routes</p>
  </div>
</div>

{#if canWrite && editing}
  <fieldset>
    <legend>Edit access policy</legend>
    <form onsubmit={saveEdit}>
      <div class="field-row">
        <div class="field">
          <label for="ap-edit-name">Name</label>
          <input id="ap-edit-name" type="text" bind:value={editName} required />
        </div>
        <div class="field">
          <label for="ap-edit-mode">Mode</label>
          <select id="ap-edit-mode" bind:value={editMode}>
            <option value="all">all</option>
            <option value="any">any</option>
          </select>
        </div>
        <div class="field">
          <label for="ap-edit-ttl">Cookie TTL</label>
          <input id="ap-edit-ttl" type="text" bind:value={editCookieTtl} placeholder="24h" />
        </div>
      </div>
      <AccessRuleList bind:rules={editRules} idPrefix="ap-edit" keepHash />
      <div class="field-row">
        <div class="field-btn">
          <button type="submit" class="btn btn-primary" disabled={saving || !canSave}>
            {saving ? 'Saving…' : 'Save policy'}
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
    <legend>Add access policy</legend>
    <form onsubmit={createPolicy}>
      <div class="field-row">
        <div class="field">
          <label for="ap-name">Name</label>
          <input id="ap-name" type="text" bind:value={name} required />
        </div>
        <div class="field">
          <label for="ap-mode">Mode</label>
          <select id="ap-mode" bind:value={mode}>
            <option value="all">all</option>
            <option value="any">any</option>
          </select>
        </div>
        <div class="field">
          <label for="ap-ttl">Cookie TTL</label>
          <input id="ap-ttl" type="text" bind:value={cookieTtl} placeholder="24h" />
        </div>
      </div>
      <AccessRuleList bind:rules={createRules} idPrefix="ap-create" />
      <div class="field-btn">
        <button type="submit" class="btn btn-primary" disabled={submitting || !canCreate}>
          {submitting ? 'Creating…' : 'Create policy'}
        </button>
      </div>
    </form>
  </fieldset>
{/if}

{#if loading}
  <p class="alert alert-loading">Loading access policies…</p>
{:else if error}
  <p class="alert alert-error">{error}</p>
{:else}
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Mode</th>
        <th>Rules</th>
        <th>Cookie TTL</th>
        {#if canWrite}<th class="actions">Actions</th>{/if}
      </tr>
    </thead>
    <tbody>
      {#each policies as p (p.id)}
        <tr>
          <td>{p.name}</td>
          <td class="mono">{p.mode}</td>
          <td class="muted">{(p.rules ?? []).map((r) => r.type).join(', ') || '—'}</td>
          <td class="mono">{p.cookie_ttl}</td>
          {#if canWrite}
            <td class="actions">
              <div class="actions-row">
                <button type="button" class="btn btn-sm" onclick={() => startEdit(p)}>Edit</button>
                <button type="button" class="btn btn-sm btn-danger" onclick={() => (confirmDelete = p)}>
                  Delete
                </button>
              </div>
            </td>
          {/if}
        </tr>
      {:else}
        <tr class="empty-row"><td colspan={canWrite ? 5 : 4}>No access policies</td></tr>
      {/each}
    </tbody>
  </table>
{/if}

<ConfirmDialog
  open={confirmDelete !== null}
  title="Delete access policy"
  message={`Remove policy "${confirmDelete?.name}"?`}
  confirmLabel="Delete"
  danger
  onconfirm={confirmRemove}
  oncancel={() => (confirmDelete = null)}
/>
