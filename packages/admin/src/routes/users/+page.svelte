<script lang="ts">
  import { onMount } from 'svelte'
  import { api, APIError, type User, type Role } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canManageOwners } from '$lib/rbac'
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte'

  const roles: Role[] = ['viewer', 'admin', 'owner']

  let users = $state<User[]>([])
  let loading = $state(true)
  let error = $state('')
  let username = $state('')
  let password = $state('')
  let role = $state<Role>('viewer')
  let creating = $state(false)
  let confirmDelete = $state<User | null>(null)

  const canManageAllRoles = $derived(canManageOwners(auth.role))
  const availableRoles = $derived(canManageAllRoles ? roles : roles.filter((r) => r !== 'owner'))

  async function load() {
    loading = true
    try {
      const res = await api.users.list()
      users = res.users
      error = ''
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load users'
    } finally {
      loading = false
    }
  }

  async function createUser(event: SubmitEvent) {
    event.preventDefault()
    const name = username.trim()
    if (!name || !password) return
    creating = true
    try {
      await api.users.create(name, password, role)
      toast.info(`User ${name} created`)
      username = ''
      password = ''
      role = 'viewer'
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to create user')
    } finally {
      creating = false
    }
  }

  function canEdit(user: User): boolean {
    return user.role !== 'owner' || canManageAllRoles
  }

  async function toggleDisabled(user: User) {
    try {
      await api.users.update(user.id, { disabled: !user.disabled })
      toast.info(`${user.username} ${user.disabled ? 'enabled' : 'disabled'}`)
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to update user')
    }
  }

  async function changeRole(user: User, next: string) {
    const nextRole = next as Role
    if (nextRole === user.role) return
    try {
      await api.users.update(user.id, { role: nextRole })
      toast.info(`Updated ${user.username} role to ${nextRole}`)
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to update role')
    }
  }

  async function confirmRemove() {
    if (!confirmDelete) return
    const user = confirmDelete
    confirmDelete = null
    try {
      await api.users.remove(user.id)
      toast.info(`Removed ${user.username}`)
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to remove user')
    }
  }

  onMount(load)
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Users</h1>
    <p class="page-sub">Admin console accounts and roles</p>
  </div>
</div>

<fieldset>
  <legend>Add user</legend>
  <form class="field-row" onsubmit={createUser}>
    <div class="field">
      <label for="new-username">Username</label>
      <input id="new-username" type="text" bind:value={username} required />
    </div>
    <div class="field">
      <label for="new-password">Password</label>
      <input id="new-password" type="password" bind:value={password} required />
    </div>
    <div class="field">
      <label for="new-role">Role</label>
      <select id="new-role" bind:value={role}>
        {#each availableRoles as r (r)}
          <option value={r}>{r}</option>
        {/each}
      </select>
    </div>
    <div class="field-btn">
      <button type="submit" class="btn btn-primary" disabled={creating || !username.trim() || !password}>
        {creating ? 'Creating…' : 'Create user'}
      </button>
    </div>
  </form>
</fieldset>

{#if loading}
  <p class="alert alert-loading">Loading users…</p>
{:else if error}
  <p class="alert alert-error">{error}</p>
{:else}
  <table>
    <thead>
      <tr>
        <th>Username</th>
        <th>Role</th>
        <th>Status</th>
        <th class="actions">Actions</th>
      </tr>
    </thead>
    <tbody>
      {#each users as user (user.id)}
        <tr>
          <td>{user.username}</td>
          <td>
            {#if canEdit(user)}
              <select value={user.role} onchange={(e) => changeRole(user, e.currentTarget.value)}>
                {#each availableRoles as r (r)}
                  <option value={r}>{r}</option>
                {/each}
                {#if user.role === 'owner' && !availableRoles.includes('owner')}
                  <option value="owner">owner</option>
                {/if}
              </select>
            {:else}
              <span class="badge badge-{user.role}">{user.role}</span>
            {/if}
          </td>
          <td>
            <span class="muted">{user.disabled ? 'disabled' : 'active'}</span>
          </td>
          <td class="actions">
            {#if canEdit(user)}
              <div class="actions-row">
                <button type="button" class="btn btn-sm" onclick={() => toggleDisabled(user)}>
                  {user.disabled ? 'Enable' : 'Disable'}
                </button>
                <button type="button" class="btn btn-sm btn-danger" onclick={() => (confirmDelete = user)}>
                  Delete
                </button>
              </div>
            {/if}
          </td>
        </tr>
      {:else}
        <tr class="empty-row"><td colspan="4">No users</td></tr>
      {/each}
    </tbody>
  </table>
{/if}

<ConfirmDialog
  open={confirmDelete !== null}
  title="Delete user"
  message={`Delete the account "${confirmDelete?.username}"? This cannot be undone.`}
  confirmLabel="Delete"
  danger
  onconfirm={confirmRemove}
  oncancel={() => (confirmDelete = null)}
/>
