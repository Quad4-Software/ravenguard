<script lang="ts">
  import { onMount } from 'svelte'
  import { api, APIError, type Route, type Upstream, type AccessPolicy, type APISchema } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canWriteConfig } from '$lib/rbac'
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte'

  let routes = $state<Route[]>([])
  let upstreams = $state<Upstream[]>([])
  let policies = $state<AccessPolicy[]>([])
  let schemas = $state<APISchema[]>([])
  let loading = $state(true)
  let error = $state('')
  let name = $state('')
  let hosts = $state('')
  let pathPrefix = $state('/')
  let upstreamId = $state('')
  let enabled = $state(true)
  let stripPrefix = $state(false)
  let priority = $state(0)
  let accessPolicyId = $state('')
  let openapiSchemaId = $state('')
  let submitting = $state(false)
  let saving = $state(false)
  let confirmDelete = $state<Route | null>(null)
  let editing = $state<Route | null>(null)

  let editName = $state('')
  let editHosts = $state('')
  let editPathPrefix = $state('/')
  let editUpstreamId = $state('')
  let editAccessPolicyId = $state('')
  let editOpenapiSchemaId = $state('')
  let editPriority = $state(0)
  let editStripPrefix = $state(false)
  let editEnabled = $state(true)

  const canWrite = $derived(canWriteConfig(auth.role))

  function upstreamName(id: string): string {
    return upstreams.find((u) => u.id === id)?.name ?? id
  }

  function policyName(id: string | null | undefined): string {
    if (!id) return '—'
    return policies.find((p) => p.id === id)?.name ?? id
  }

  function schemaName(id: string | null | undefined): string {
    if (!id) return '—'
    return schemas.find((s) => s.id === id)?.name ?? id
  }

  function parseHosts(value: string): string[] {
    return value
      .split(',')
      .map((h) => h.trim())
      .filter(Boolean)
  }

  function startEdit(rt: Route) {
    editing = rt
    editName = rt.name
    editHosts = (rt.hosts ?? []).join(', ')
    editPathPrefix = rt.path_prefix || '/'
    editUpstreamId = rt.upstream_id
    editAccessPolicyId = rt.access_policy_id ?? ''
    editOpenapiSchemaId = rt.openapi_schema_id ?? ''
    editPriority = rt.priority
    editStripPrefix = rt.strip_prefix
    editEnabled = rt.enabled
  }

  function cancelEdit() {
    editing = null
  }

  async function load() {
    loading = true
    try {
      const [rt, up, pol, sch] = await Promise.all([
        api.routes.list(),
        api.upstreams.list(),
        api.accessPolicies.list(),
        api.apiSchemas.list(),
      ])
      routes = rt.routes ?? []
      upstreams = up.upstreams ?? []
      policies = pol.access_policies ?? []
      schemas = sch.api_schemas ?? []
      if (!upstreamId && upstreams.length > 0) {
        upstreamId = upstreams[0].id
      }
      error = ''
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load routes'
    } finally {
      loading = false
    }
  }

  async function createRoute(event: SubmitEvent) {
    event.preventDefault()
    const n = name.trim()
    const hostList = parseHosts(hosts)
    if (!n || hostList.length === 0 || !upstreamId) return
    submitting = true
    try {
      await api.routes.create({
        name: n,
        hosts: hostList,
        path_prefix: pathPrefix.trim() || '/',
        upstream_id: upstreamId,
        enabled,
        strip_prefix: stripPrefix,
        priority: Number(priority) || 0,
        access_policy_id: accessPolicyId || null,
        openapi_schema_id: openapiSchemaId || null,
      })
      toast.info(`Route ${n} created`)
      name = ''
      hosts = ''
      pathPrefix = '/'
      enabled = true
      stripPrefix = false
      priority = 0
      accessPolicyId = ''
      openapiSchemaId = ''
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to create route')
    } finally {
      submitting = false
    }
  }

  async function saveEdit(event: SubmitEvent) {
    event.preventDefault()
    if (!editing) return
    const n = editName.trim()
    const hostList = parseHosts(editHosts)
    if (!n || hostList.length === 0 || !editUpstreamId) return
    saving = true
    try {
      await api.routes.update(editing.id, {
        name: n,
        hosts: hostList,
        path_prefix: editPathPrefix.trim() || '/',
        upstream_id: editUpstreamId,
        access_policy_id: editAccessPolicyId || null,
        openapi_schema_id: editOpenapiSchemaId || null,
        priority: Number(editPriority) || 0,
        strip_prefix: editStripPrefix,
        enabled: editEnabled,
      })
      toast.info(`Route ${n} updated`)
      editing = null
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to update route')
    } finally {
      saving = false
    }
  }

  async function confirmRemove() {
    if (!confirmDelete) return
    const rt = confirmDelete
    confirmDelete = null
    try {
      await api.routes.remove(rt.id)
      toast.info(`Removed ${rt.name}`)
      if (editing?.id === rt.id) editing = null
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to remove route')
    }
  }

  onMount(load)
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Routes</h1>
    <p class="page-sub">Host and path mappings to upstreams</p>
  </div>
</div>

{#if canWrite && editing}
  <fieldset>
    <legend>Edit route</legend>
    <form class="field-row" onsubmit={saveEdit}>
      <div class="field">
        <label for="rt-edit-name">Name</label>
        <input id="rt-edit-name" type="text" bind:value={editName} required />
      </div>
      <div class="field">
        <label for="rt-edit-hosts">Hosts</label>
        <input id="rt-edit-hosts" type="text" bind:value={editHosts} placeholder="example.com, www.example.com" required />
      </div>
      <div class="field">
        <label for="rt-edit-path">Path prefix</label>
        <input id="rt-edit-path" type="text" bind:value={editPathPrefix} />
      </div>
      <div class="field">
        <label for="rt-edit-upstream">Upstream</label>
        <select id="rt-edit-upstream" bind:value={editUpstreamId} required>
          {#each upstreams as up (up.id)}
            <option value={up.id}>{up.name}</option>
          {/each}
        </select>
      </div>
      <div class="field">
        <label for="rt-edit-policy">Access policy</label>
        <select id="rt-edit-policy" bind:value={editAccessPolicyId}>
          <option value="">None</option>
          {#each policies as p (p.id)}
            <option value={p.id}>{p.name}</option>
          {/each}
        </select>
      </div>
      <div class="field">
        <label for="rt-edit-schema">API schema</label>
        <select id="rt-edit-schema" bind:value={editOpenapiSchemaId}>
          <option value="">None</option>
          {#each schemas as s (s.id)}
            <option value={s.id}>{s.name}</option>
          {/each}
        </select>
      </div>
      <div class="field">
        <label for="rt-edit-priority">Priority</label>
        <input id="rt-edit-priority" type="number" bind:value={editPriority} />
      </div>
      <div class="field">
        <label for="rt-edit-enabled">
          <input id="rt-edit-enabled" type="checkbox" bind:checked={editEnabled} />
          Enabled
        </label>
      </div>
      <div class="field">
        <label for="rt-edit-strip">
          <input id="rt-edit-strip" type="checkbox" bind:checked={editStripPrefix} />
          Strip prefix
        </label>
      </div>
      <div class="field-btn">
        <button
          type="submit"
          class="btn btn-primary"
          disabled={saving || !editName.trim() || !editHosts.trim() || !editUpstreamId}
        >
          {saving ? 'Saving…' : 'Save route'}
        </button>
      </div>
      <div class="field-btn">
        <button type="button" class="btn" onclick={cancelEdit}>Cancel</button>
      </div>
    </form>
  </fieldset>
{:else if canWrite}
  <fieldset>
    <legend>Add route</legend>
    <form class="field-row" onsubmit={createRoute}>
      <div class="field">
        <label for="rt-name">Name</label>
        <input id="rt-name" type="text" bind:value={name} required />
      </div>
      <div class="field">
        <label for="rt-hosts">Hosts</label>
        <input id="rt-hosts" type="text" bind:value={hosts} placeholder="example.com, www.example.com" required />
      </div>
      <div class="field">
        <label for="rt-path">Path prefix</label>
        <input id="rt-path" type="text" bind:value={pathPrefix} />
      </div>
      <div class="field">
        <label for="rt-upstream">Upstream</label>
        <select id="rt-upstream" bind:value={upstreamId} required>
          {#each upstreams as up (up.id)}
            <option value={up.id}>{up.name}</option>
          {/each}
        </select>
      </div>
      <div class="field">
        <label for="rt-priority">Priority</label>
        <input id="rt-priority" type="number" bind:value={priority} />
      </div>
      <div class="field">
        <label for="rt-policy">Access policy</label>
        <select id="rt-policy" bind:value={accessPolicyId}>
          <option value="">None</option>
          {#each policies as p (p.id)}
            <option value={p.id}>{p.name}</option>
          {/each}
        </select>
      </div>
      <div class="field">
        <label for="rt-schema">API schema</label>
        <select id="rt-schema" bind:value={openapiSchemaId}>
          <option value="">None</option>
          {#each schemas as s (s.id)}
            <option value={s.id}>{s.name}</option>
          {/each}
        </select>
      </div>
      <div class="field">
        <label for="rt-enabled">
          <input id="rt-enabled" type="checkbox" bind:checked={enabled} />
          Enabled
        </label>
      </div>
      <div class="field">
        <label for="rt-strip">
          <input id="rt-strip" type="checkbox" bind:checked={stripPrefix} />
          Strip prefix
        </label>
      </div>
      <div class="field-btn">
        <button
          type="submit"
          class="btn btn-primary"
          disabled={submitting || !name.trim() || !hosts.trim() || !upstreamId}
        >
          {submitting ? 'Creating…' : 'Create route'}
        </button>
      </div>
    </form>
  </fieldset>
{/if}

{#if loading}
  <p class="alert alert-loading">Loading routes…</p>
{:else if error}
  <p class="alert alert-error">{error}</p>
{:else}
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Hosts</th>
        <th>Path</th>
        <th>Upstream</th>
        <th>Priority</th>
        <th>Enabled</th>
        <th>Access</th>
        <th>Schema</th>
        {#if canWrite}<th class="actions">Actions</th>{/if}
      </tr>
    </thead>
    <tbody>
      {#each routes as rt (rt.id)}
        <tr>
          <td>{rt.name}</td>
          <td class="mono">{rt.hosts?.join(', ') ?? ''}</td>
          <td class="mono">{rt.path_prefix}</td>
          <td>{upstreamName(rt.upstream_id)}</td>
          <td class="mono">{rt.priority}</td>
          <td class="muted">{rt.enabled ? 'yes' : 'no'}</td>
          <td class="muted">{policyName(rt.access_policy_id)}</td>
          <td class="muted">{schemaName(rt.openapi_schema_id)}</td>
          {#if canWrite}
            <td class="actions">
              <div class="actions-row">
                <button type="button" class="btn btn-sm" onclick={() => startEdit(rt)}>Edit</button>
                <button type="button" class="btn btn-sm btn-danger" onclick={() => (confirmDelete = rt)}>
                  Delete
                </button>
              </div>
            </td>
          {/if}
        </tr>
      {:else}
        <tr class="empty-row"><td colspan={canWrite ? 9 : 8}>No routes</td></tr>
      {/each}
    </tbody>
  </table>
{/if}

<ConfirmDialog
  open={confirmDelete !== null}
  title="Delete route"
  message={`Remove route "${confirmDelete?.name}"?`}
  confirmLabel="Delete"
  danger
  onconfirm={confirmRemove}
  oncancel={() => (confirmDelete = null)}
/>
