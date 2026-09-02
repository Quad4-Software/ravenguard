<script lang="ts">
  import { onMount } from 'svelte'
  import { api, APIError, type QFeedsSafe, type QFeedsStatus } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canWriteConfig, canWriteOps } from '$lib/rbac'
  import Metric from '$lib/components/Metric.svelte'

  let status = $state<QFeedsStatus | null>(null)
  let form = $state<QFeedsSafe | null>(null)
  let feedsText = $state('')
  let loading = $state(true)
  let error = $state('')
  let saving = $state(false)
  let refreshing = $state(false)

  const canWrite = $derived(canWriteConfig(auth.role))
  const canOps = $derived(canWriteOps(auth.role))

  async function load() {
    loading = true
    try {
      const res = await api.qfeeds.get()
      status = res.status
      form = { ...res.config, api_token: '' }
      feedsText = (res.config.feeds ?? []).join('\n')
      error = ''
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load q-feeds'
    } finally {
      loading = false
    }
  }

  async function save(event: SubmitEvent) {
    event.preventDefault()
    if (!form) return
    saving = true
    try {
      const payload: QFeedsSafe = {
        ...form,
        feeds: feedsText
          .split(/[\n,]+/)
          .map((s) => s.trim())
          .filter(Boolean),
      }
      if (!payload.api_token) delete payload.api_token
      const res = await api.qfeeds.update(payload)
      status = res.status
      form = { ...res.config, api_token: '' }
      feedsText = (res.config.feeds ?? []).join('\n')
      toast.info('Q-Feeds updated')
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'save failed')
    } finally {
      saving = false
    }
  }

  async function refresh() {
    refreshing = true
    try {
      const res = await api.qfeeds.refresh()
      status = res.status
      toast.info('Q-Feeds refreshed')
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'refresh failed')
    } finally {
      refreshing = false
    }
  }

  onMount(load)
</script>

<div class="page-head">
  <div class="page-head-text">
    <h1 class="page-title">Q-Feeds</h1>
    <p class="page-sub">Threat feed cache and live settings</p>
  </div>
  {#if canOps}
    <button type="button" class="btn" onclick={refresh} disabled={refreshing || !status?.enabled}>
      {refreshing ? 'Refreshing…' : 'Refresh now'}
    </button>
  {/if}
</div>

{#if loading}
  <p class="alert alert-loading">Loading…</p>
{:else if error}
  <p class="alert alert-error">{error}</p>
{:else if form && status}
  <div class="metric-grid">
    <Metric label="State" value={status.enabled ? (status.failed ? 'failed' : 'active') : 'off'} tone={status.enabled ? (status.failed ? 'bad' : 'ok') : 'default'} />
    <Metric label="IP hits" value={String(status.ip_count)} />
    <Metric label="Domain hits" value={String(status.domain_count)} />
    <Metric label="Token" value={status.has_token ? 'set' : 'missing'} tone={status.has_token ? 'ok' : 'bad'} />
  </div>

  <form onsubmit={save}>
    <fieldset>
      <legend>Settings</legend>
      <div class="field checkbox-field">
        <input id="qf-enabled" type="checkbox" bind:checked={form.enabled} disabled={!canWrite} />
        <label for="qf-enabled">Enabled</label>
      </div>
      <div class="field">
        <label for="qf-feeds">Feeds (one per line)</label>
        <textarea id="qf-feeds" rows="4" bind:value={feedsText} disabled={!canWrite}></textarea>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="qf-refresh">Refresh</label>
          <input id="qf-refresh" type="text" bind:value={form.refresh} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="qf-on-error">On error</label>
          <select id="qf-on-error" bind:value={form.on_error} disabled={!canWrite}>
            <option value="fail_open">fail_open</option>
            <option value="fail_closed">fail_closed</option>
          </select>
        </div>
        <div class="field">
          <label for="qf-limit">Limit</label>
          <input id="qf-limit" type="number" min="0" bind:value={form.limit} disabled={!canWrite} />
        </div>
      </div>
      <div class="field">
        <label for="qf-base">Base URL</label>
        <input id="qf-base" type="text" bind:value={form.base_url} disabled={!canWrite} />
      </div>
      <div class="field">
        <label for="qf-token">API token (leave blank to keep)</label>
        <input id="qf-token" type="password" bind:value={form.api_token} disabled={!canWrite} autocomplete="off" />
      </div>
    </fieldset>
    {#if canWrite}
      <button type="submit" class="btn btn-primary" disabled={saving}>{saving ? 'Saving…' : 'Save Q-Feeds'}</button>
    {/if}
  </form>
{/if}
