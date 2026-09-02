<script lang="ts">
  import { onMount } from 'svelte'
  import { api, APIError, type APIToken, type Role } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte'

  const roles: Role[] = ['viewer', 'admin', 'owner']

  let tokens = $state<APIToken[]>([])
  let loading = $state(true)
  let error = $state('')
  let name = $state('')
  let role = $state<Role | ''>('')
  let expiresIn = $state('')
  let creating = $state(false)
  let newSecret = $state('')
  let confirmRevoke = $state<APIToken | null>(null)

  async function load() {
    loading = true
    try {
      const res = await api.tokens.list()
      tokens = res.tokens
      error = ''
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load tokens'
    } finally {
      loading = false
    }
  }

  async function createToken(event: SubmitEvent) {
    event.preventDefault()
    const tokenName = name.trim()
    if (!tokenName) return
    creating = true
    try {
      const res = await api.tokens.create(tokenName, role || undefined, expiresIn.trim() || undefined)
      newSecret = res.secret
      name = ''
      role = ''
      expiresIn = ''
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to create token')
    } finally {
      creating = false
    }
  }

  async function confirmDoRevoke() {
    if (!confirmRevoke) return
    const tok = confirmRevoke
    confirmRevoke = null
    try {
      await api.tokens.revoke(tok.id)
      toast.info(`Revoked ${tok.name}`)
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to revoke token')
    }
  }

  onMount(load)
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Tokens</h1>
    <p class="page-sub">API tokens for automated access</p>
  </div>
</div>

{#if newSecret}
  <div class="alert">
    <p><strong>Token secret (shown once):</strong></p>
    <p class="mono secret-value">{newSecret}</p>
    <button type="button" class="btn btn-sm" onclick={() => (newSecret = '')}>Dismiss</button>
  </div>
{/if}

<fieldset>
  <legend>Create token</legend>
  <form class="field-row" onsubmit={createToken}>
    <div class="field">
      <label for="tok-name">Name</label>
      <input id="tok-name" type="text" bind:value={name} required />
    </div>
    <div class="field">
      <label for="tok-role">Role (defaults to your role)</label>
      <select id="tok-role" bind:value={role}>
        <option value="">default</option>
        {#each roles as r (r)}
          <option value={r}>{r}</option>
        {/each}
      </select>
    </div>
    <div class="field">
      <label for="tok-expires">Expires in (e.g. 720h)</label>
      <input id="tok-expires" type="text" bind:value={expiresIn} placeholder="never" />
    </div>
    <div class="field-btn">
      <button type="submit" class="btn btn-primary" disabled={creating || !name.trim()}>
        {creating ? 'Creating…' : 'Create token'}
      </button>
    </div>
  </form>
</fieldset>

{#if loading}
  <p class="alert alert-loading">Loading tokens…</p>
{:else if error}
  <p class="alert alert-error">{error}</p>
{:else}
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Role</th>
        <th>Created</th>
        <th>Expires</th>
        <th>Last used</th>
        <th class="actions">Actions</th>
      </tr>
    </thead>
    <tbody>
      {#each tokens as tok (tok.id)}
        <tr>
          <td>{tok.name}</td>
          <td><span class="badge badge-{tok.role}">{tok.role}</span></td>
          <td class="muted">{tok.created_at}</td>
          <td class="muted">{tok.expires_at ?? 'never'}</td>
          <td class="muted">{tok.last_used_at ?? 'never'}</td>
          <td class="actions">
            <button type="button" class="btn btn-sm btn-danger" onclick={() => (confirmRevoke = tok)}>
              Revoke
            </button>
          </td>
        </tr>
      {:else}
        <tr class="empty-row"><td colspan="6">No tokens</td></tr>
      {/each}
    </tbody>
  </table>
{/if}

<ConfirmDialog
  open={confirmRevoke !== null}
  title="Revoke token"
  message={`Revoke the token "${confirmRevoke?.name}"? Any client using it will lose access immediately.`}
  confirmLabel="Revoke"
  danger
  onconfirm={confirmDoRevoke}
  oncancel={() => (confirmRevoke = null)}
/>
