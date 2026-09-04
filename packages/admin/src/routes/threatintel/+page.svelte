<script lang="ts">
  import { onMount } from 'svelte'
  import { api, APIError } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canWriteOps } from '$lib/rbac'

  let loading = $state(true)
  let error = $state('')
  let exportRawIP = $state(false)
  let status = $state<Record<string, unknown>>({})
  let ingestText = $state('type,value,ttl_seconds,reason\nipv4,203.0.113.10,3600,example\n')
  let ingestFormat = $state<'csv' | 'stix'>('csv')
  let ingestURL = $state('')
  let reportIP = $state('')
  let reportConfirm = $state(false)
  let busy = $state(false)

  const canWrite = $derived(canWriteOps(auth.role))

  async function load() {
    loading = true
    try {
      const cfg = await api.threatintel.config()
      exportRawIP = cfg.export_raw_ip
      status = cfg.status ?? {}
      error = ''
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load threat intel'
    } finally {
      loading = false
    }
  }

  async function savePrivacy() {
    if (!canWrite) return
    busy = true
    try {
      await api.threatintel.putConfig({ export_raw_ip: exportRawIP })
      toast.info('Saved')
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'save failed')
    } finally {
      busy = false
    }
  }

  async function doIngest() {
    if (!canWrite) return
    busy = true
    try {
      const res = await api.threatintel.ingest(ingestText, ingestFormat)
      toast.info(`Ingested ${res.stored} (accepted ${res.accepted}, skipped ${res.skipped})`)
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'ingest failed')
    } finally {
      busy = false
    }
  }

  async function doIngestURL(event: SubmitEvent) {
    event.preventDefault()
    if (!canWrite || !ingestURL.trim()) return
    busy = true
    try {
      const res = await api.threatintel.ingestURL(ingestURL.trim())
      toast.info(`URL ingest stored ${res.stored}`)
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'url ingest failed')
    } finally {
      busy = false
    }
  }

  async function abuseSync() {
    if (!canWrite) return
    busy = true
    try {
      const res = await api.threatintel.abuseSync()
      toast.info(`AbuseIPDB synced ${res.stored}`)
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'AbuseIPDB sync failed')
    } finally {
      busy = false
    }
  }

  async function mispSync() {
    if (!canWrite) return
    busy = true
    try {
      const res = await api.threatintel.mispSync()
      toast.info(`MISP synced ${res.stored}`)
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'MISP sync failed')
    } finally {
      busy = false
    }
  }

  async function abuseReport(event: SubmitEvent) {
    event.preventDefault()
    if (!canWrite || !reportIP.trim()) return
    busy = true
    try {
      await api.threatintel.abuseReport({
        ip: reportIP.trim(),
        confirm_raw: reportConfirm || exportRawIP,
        comment: 'RavenGuard operator report',
      })
      toast.info('Reported to AbuseIPDB')
      reportIP = ''
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'report failed')
    } finally {
      busy = false
    }
  }

  onMount(load)
</script>

<div class="page-head">
  <div class="page-head-text">
    <h1 class="page-title">Threat intel</h1>
    <p class="page-sub">Export STIX/CSV, ingest feeds, and sync AbuseIPDB or MISP into the fleet ledger</p>
  </div>
</div>

{#if loading}
  <p class="alert alert-loading">Loading…</p>
{:else if error}
  <p class="alert alert-error">{error}</p>
{:else}
  <section class="section">
    <h2 class="section-title">Export</h2>
    <p class="page-sub">Pollers can use session auth or a configured export bearer token.</p>
    <div class="field-row">
      <a class="btn btn-primary" href={api.threatintel.exportSTIXURL()} download="ravenguard.stix.json">
        Download STIX
      </a>
      <a class="btn" href={api.threatintel.exportCSVURL()} download="ravenguard-threatintel.csv">
        Download CSV
      </a>
    </div>
    {#if canWrite}
      <div class="field checkbox-field">
        <input id="ti-export-raw" type="checkbox" bind:checked={exportRawIP} />
        <label for="ti-export-raw">Export raw IPs (off by default, bind/UA/domain still export)</label>
      </div>
      <button type="button" class="btn btn-primary" disabled={busy} onclick={savePrivacy}>Save privacy</button>
    {/if}
  </section>

  <section class="section">
    <h2 class="section-title">Ingest</h2>
    {#if canWrite}
      <div class="field">
        <label for="ti-format">Format</label>
        <select id="ti-format" bind:value={ingestFormat}>
          <option value="csv">CSV</option>
          <option value="stix">STIX</option>
        </select>
      </div>
      <div class="field">
        <label for="ti-body">Payload</label>
        <textarea id="ti-body" rows="8" bind:value={ingestText} class="mono"></textarea>
      </div>
      <button type="button" class="btn btn-primary" disabled={busy} onclick={doIngest}>Ingest body</button>
      <form class="field-row" onsubmit={doIngestURL}>
        <div class="field">
          <label for="ti-url">Feed URL</label>
          <input id="ti-url" type="text" bind:value={ingestURL} placeholder="https://…" />
        </div>
        <div class="field-btn">
          <button type="submit" class="btn" disabled={busy || !ingestURL.trim()}>
            Ingest URL
          </button>
        </div>
      </form>
    {:else}
      <p class="muted">Write access required to ingest.</p>
    {/if}
  </section>

  <section class="section">
    <h2 class="section-title">Exchanges</h2>
    {#if canWrite}
      <div class="field-row">
        <button type="button" class="btn btn-primary" disabled={busy} onclick={abuseSync}>AbuseIPDB sync</button>
        <button type="button" class="btn" disabled={busy} onclick={mispSync}>MISP sync</button>
      </div>
      <form class="field-row" onsubmit={abuseReport}>
        <div class="field">
          <label for="report-ip">Report IP to AbuseIPDB</label>
          <input id="report-ip" type="text" bind:value={reportIP} placeholder="203.0.113.10" />
        </div>
        <div class="field checkbox-field">
          <input id="report-confirm" type="checkbox" bind:checked={reportConfirm} />
          <label for="report-confirm">Confirm raw IP report</label>
        </div>
        <div class="field-btn">
          <button type="submit" class="btn btn-danger" disabled={busy || !reportIP.trim()}>Report</button>
        </div>
      </form>
    {/if}
    <p class="muted mono wrap-text section-note">Last status: {JSON.stringify(status)}</p>
  </section>
{/if}
