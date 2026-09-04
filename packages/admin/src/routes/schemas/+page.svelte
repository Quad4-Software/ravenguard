<script lang="ts">
  import { onMount } from 'svelte'
  import { api, APIError, type APISchema } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canWriteConfig } from '$lib/rbac'
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte'

  let schemas = $state<APISchema[]>([])
  let loading = $state(true)
  let error = $state('')
  let name = $state('')
  let mode = $state<'block' | 'detect'>('block')
  let specText = $state('')
  let submitting = $state(false)
  let saving = $state(false)
  let confirmDelete = $state<APISchema | null>(null)
  let editing = $state<APISchema | null>(null)
  let editName = $state('')
  let editMode = $state<'block' | 'detect'>('block')
  let editSpec = $state('')

  const canWrite = $derived(canWriteConfig(auth.role))

  function startEdit(s: APISchema) {
    editing = s
    editName = s.name
    editMode = s.mode === 'detect' ? 'detect' : 'block'
    editSpec = s.spec_text
  }

  function cancelEdit() {
    editing = null
  }

  function resetCreate() {
    name = ''
    mode = 'block'
    specText = ''
  }

  async function load() {
    loading = true
    try {
      const res = await api.apiSchemas.list()
      schemas = res.api_schemas ?? []
      error = ''
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load schemas'
    } finally {
      loading = false
    }
  }

  async function createSchema(event: SubmitEvent) {
    event.preventDefault()
    const n = name.trim()
    const spec = specText.trim()
    if (!n || !spec) return
    submitting = true
    try {
      await api.apiSchemas.create({ name: n, mode, spec_text: spec })
      toast.success('Schema created')
      resetCreate()
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'create failed')
    } finally {
      submitting = false
    }
  }

  async function saveEdit(event: SubmitEvent) {
    event.preventDefault()
    if (!editing) return
    saving = true
    try {
      await api.apiSchemas.update(editing.id, {
        name: editName.trim(),
        mode: editMode,
        spec_text: editSpec.trim(),
      })
      toast.success('Schema updated')
      cancelEdit()
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'update failed')
    } finally {
      saving = false
    }
  }

  async function removeSchema() {
    if (!confirmDelete) return
    try {
      await api.apiSchemas.remove(confirmDelete.id)
      toast.success('Schema deleted')
      confirmDelete = null
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'delete failed')
    }
  }

  onMount(load)
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">API schemas</h1>
    <p class="page-sub">OpenAPI 3 documents enforced as positive security gates on routes</p>
  </div>
</div>

{#if error}
  <p class="error">{error}</p>
{/if}

{#if canWrite}
  <form class="card stack" onsubmit={createSchema}>
    <h2 class="section-title">Add schema</h2>
    <div class="field-row">
      <div class="field grow">
        <label for="schema-name">Name</label>
        <input id="schema-name" bind:value={name} required />
      </div>
      <div class="field">
        <label for="schema-mode">Mode</label>
        <select id="schema-mode" bind:value={mode}>
          <option value="block">block</option>
          <option value="detect">detect</option>
        </select>
      </div>
    </div>
    <div class="field">
      <label for="schema-spec">OpenAPI YAML or JSON</label>
      <textarea id="schema-spec" rows="10" bind:value={specText} required class="mono"></textarea>
    </div>
    <button type="submit" class="btn" disabled={submitting || !name.trim() || !specText.trim()}>
      {submitting ? 'Creating…' : 'Create'}
    </button>
  </form>
{/if}

{#if loading}
  <p class="muted">Loading…</p>
{:else if schemas.length === 0}
  <p class="muted">No API schemas yet</p>
{:else}
  <div class="stack">
    {#each schemas as s (s.id)}
      <div class="card stack">
        {#if editing?.id === s.id}
          <form class="stack" onsubmit={saveEdit}>
            <div class="field-row">
              <div class="field grow">
                <label for="edit-name-{s.id}">Name</label>
                <input id="edit-name-{s.id}" bind:value={editName} required />
              </div>
              <div class="field">
                <label for="edit-mode-{s.id}">Mode</label>
                <select id="edit-mode-{s.id}" bind:value={editMode}>
                  <option value="block">block</option>
                  <option value="detect">detect</option>
                </select>
              </div>
            </div>
            <div class="field">
              <label for="edit-spec-{s.id}">Spec</label>
              <textarea id="edit-spec-{s.id}" rows="10" bind:value={editSpec} class="mono" required></textarea>
            </div>
            <div class="field-row">
              <button type="submit" class="btn" disabled={saving}>Save</button>
              <button type="button" class="btn btn-ghost" onclick={cancelEdit}>Cancel</button>
            </div>
          </form>
        {:else}
          <div class="row-between">
            <div>
              <strong>{s.name}</strong>
              <span class="muted"> · {s.mode}</span>
            </div>
            {#if canWrite}
              <div class="field-row">
                <button type="button" class="btn btn-ghost" onclick={() => startEdit(s)}>Edit</button>
                <button type="button" class="btn btn-ghost" onclick={() => (confirmDelete = s)}>Delete</button>
              </div>
            {/if}
          </div>
          <pre class="spec-preview mono">{s.spec_text.slice(0, 240)}{s.spec_text.length > 240 ? '…' : ''}</pre>
        {/if}
      </div>
    {/each}
  </div>
{/if}

<ConfirmDialog
  open={!!confirmDelete}
  title="Delete schema"
  message={confirmDelete ? `Delete ${confirmDelete.name}?` : ''}
  confirmLabel="Delete"
  onconfirm={removeSchema}
  oncancel={() => (confirmDelete = null)}
/>

<style>
  .grow {
    flex: 1;
  }
  .stack {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }
  .section-title {
    margin: 0;
    font-size: 1rem;
  }
  .row-between {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.85rem;
  }
  .spec-preview {
    margin: 0;
    white-space: pre-wrap;
    opacity: 0.8;
    max-height: 8rem;
    overflow: hidden;
  }
  textarea {
    width: 100%;
  }
</style>
