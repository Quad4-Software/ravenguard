<script lang="ts">
  import { onMount } from 'svelte'
  import { api, APIError, type CertStatus } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canWriteConfig } from '$lib/rbac'
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte'

  let certs = $state<CertStatus[]>([])
  let loading = $state(true)
  let error = $state('')
  let renewing = $state<string | null>(null)
  let selected = $state<CertStatus | null>(null)
  let detailLoading = $state(false)

  let uploadHost = $state('')
  let certPem = $state('')
  let keyPem = $state('')
  let uploading = $state(false)
  let genHost = $state('')
  let genValidity = $state('365d')
  let generating = $state(false)
  let manageHosts = $state('')
  let managing = $state(false)
  let confirmDelete = $state<string | null>(null)

  const canWrite = $derived(canWriteConfig(auth.role))

  async function load() {
    loading = true
    try {
      const res = await api.certs.list()
      certs = Array.isArray(res.certs) ? res.certs : Array.isArray(res) ? (res as unknown as CertStatus[]) : []
      error = ''
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load certificates'
    } finally {
      loading = false
    }
  }

  async function openDetail(host: string) {
    detailLoading = true
    try {
      selected = await api.certs.get(host)
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to load certificate detail')
      selected = certs.find((c) => c.hostname === host) ?? null
    } finally {
      detailLoading = false
    }
  }

  async function renew(host: string) {
    renewing = host
    try {
      await api.certs.renew(host)
      toast.info(`Renew requested for ${host}`)
      await load()
      if (selected?.hostname === host) await openDetail(host)
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to renew certificate')
    } finally {
      renewing = null
    }
  }

  async function upload(event: SubmitEvent) {
    event.preventDefault()
    const host = uploadHost.trim().toLowerCase()
    if (!host || !certPem.trim() || !keyPem.trim()) return
    uploading = true
    try {
      await api.certs.upload(host, certPem, keyPem)
      toast.info(`Stored certificate for ${host}`)
      uploadHost = ''
      certPem = ''
      keyPem = ''
      await load()
      await openDetail(host)
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to upload certificate')
    } finally {
      uploading = false
    }
  }

  async function generate(event: SubmitEvent) {
    event.preventDefault()
    const host = genHost.trim().toLowerCase()
    if (!host) return
    generating = true
    try {
      const detail = await api.certs.generate(host, { validity: genValidity.trim() || '365d' })
      toast.info(`Generated self-signed certificate for ${host}`)
      genHost = ''
      await load()
      selected = detail
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to generate certificate')
    } finally {
      generating = false
    }
  }

  async function onFile(kind: 'cert' | 'key', files: FileList | null) {
    const f = files?.[0]
    if (!f) return
    const text = await f.text()
    if (kind === 'cert') certPem = text
    else keyPem = text
  }

  async function manageACME(event: SubmitEvent) {
    event.preventDefault()
    const hosts = manageHosts
      .split(/[,\s]+/)
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean)
    if (!hosts.length) return
    managing = true
    try {
      await api.certs.manage(hosts)
      toast.info(`ACME manage requested for ${hosts.join(', ')}`)
      manageHosts = ''
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to manage hosts')
    } finally {
      managing = false
    }
  }

  async function doDelete() {
    const host = confirmDelete
    confirmDelete = null
    if (!host) return
    try {
      await api.certs.remove(host)
      toast.info(`Removed certificate for ${host}`)
      if (selected?.hostname === host) selected = null
      await load()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to delete certificate')
    }
  }

  function daysClass(days?: number): string {
    if (days == null) return 'muted'
    if (days <= 7) return 'badge badge-owner'
    if (days <= 30) return 'badge badge-admin'
    return 'muted'
  }

  onMount(load)
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Certificates</h1>
    <p class="page-sub">ACME status, manual PEM upload, self-signed generation, and certificate details</p>
  </div>
  <button type="button" class="btn btn-ghost" onclick={load} disabled={loading}>Refresh</button>
</div>

{#if canWrite}
  <div class="section">
    <div class="section-title">Generate self-signed</div>
    <form class="field-row" onsubmit={generate}>
      <div class="field">
        <label for="gen-host">Hostname</label>
        <input id="gen-host" type="text" bind:value={genHost} placeholder="dev.local" />
      </div>
      <div class="field">
        <label for="gen-validity">Validity</label>
        <input id="gen-validity" type="text" bind:value={genValidity} placeholder="365d" />
      </div>
      <div class="field-btn">
        <button type="submit" class="btn btn-primary" disabled={generating || !genHost.trim()}>
          {generating ? 'Generating…' : 'Generate self-signed'}
        </button>
      </div>
    </form>
  </div>

  <div class="section">
    <div class="section-title">Upload or paste PEM</div>
    <form onsubmit={upload}>
      <div class="field-row">
        <div class="field">
          <label for="cert-host">Hostname</label>
          <input id="cert-host" type="text" bind:value={uploadHost} placeholder="app.example.com" />
        </div>
        <div class="field">
          <label for="cert-file">Certificate file</label>
          <input id="cert-file" type="file" accept=".pem,.crt,.cer,text/*" onchange={(e) => onFile('cert', e.currentTarget.files)} />
        </div>
        <div class="field">
          <label for="key-file">Private key file</label>
          <input id="key-file" type="file" accept=".pem,.key,text/*" onchange={(e) => onFile('key', e.currentTarget.files)} />
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="cert-pem">Certificate PEM (full chain)</label>
          <textarea id="cert-pem" rows="6" class="mono" bind:value={certPem} placeholder="-----BEGIN CERTIFICATE-----"></textarea>
        </div>
        <div class="field">
          <label for="key-pem">Private key PEM</label>
          <textarea id="key-pem" rows="6" class="mono" bind:value={keyPem} placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
        </div>
      </div>
      <button type="submit" class="btn btn-primary" disabled={uploading || !uploadHost.trim() || !certPem.trim() || !keyPem.trim()}>
        {uploading ? 'Saving…' : 'Save manual certificate'}
      </button>
    </form>
  </div>

  <div class="section">
    <div class="section-title">Request ACME certificate</div>
    <form class="field-row" onsubmit={manageACME}>
      <div class="field">
        <label for="acme-hosts">Hostnames</label>
        <input id="acme-hosts" type="text" bind:value={manageHosts} placeholder="app.example.com, api.example.com" />
      </div>
      <div class="field-btn">
        <button type="submit" class="btn btn-primary" disabled={managing || !manageHosts.trim()}>
          {managing ? 'Requesting…' : 'Manage with ACME'}
        </button>
      </div>
    </form>
  </div>
{/if}

{#if loading}
  <p class="alert alert-loading">Loading certificates…</p>
{:else if error}
  <p class="alert alert-error">{error}</p>
{:else}
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Hostname</th>
          <th>Source</th>
          <th>State</th>
          <th>Days left</th>
          <th>Not after</th>
          <th>Issuer</th>
          {#if canWrite}<th class="actions">Actions</th>{/if}
        </tr>
      </thead>
      <tbody>
        {#each certs as cert (cert.hostname + (cert.source ?? ''))}
          <tr>
            <td class="mono">
              <button type="button" class="btn btn-ghost btn-sm" onclick={() => openDetail(cert.hostname)}>
                {cert.hostname}
              </button>
            </td>
            <td class="muted">{cert.source || '—'}</td>
            <td class="muted">{cert.state}</td>
            <td class={daysClass(cert.days_left)}>{cert.days_left ?? '—'}</td>
            <td class="muted">{cert.not_after || '—'}</td>
            <td class="muted cell-clip">{cert.issuer || '—'}</td>
            {#if canWrite}
              <td class="actions">
                {#if cert.source === 'acme' || cert.managed}
                  <button
                    type="button"
                    class="btn btn-sm btn-primary"
                    disabled={renewing === cert.hostname}
                    onclick={() => renew(cert.hostname)}
                  >
                    {renewing === cert.hostname ? 'Renewing…' : 'Renew'}
                  </button>
                {/if}
                {#if cert.source === 'manual' || cert.source === 'selfsigned'}
                  <button type="button" class="btn btn-sm btn-ghost" onclick={() => (confirmDelete = cert.hostname)}>
                    Delete
                  </button>
                {/if}
              </td>
            {/if}
          </tr>
        {:else}
          <tr class="empty-row"><td colspan={canWrite ? 7 : 6}>No certificates yet</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

{#if selected}
  <div class="section">
    <div class="section-title">Details · {selected.hostname}</div>
    {#if detailLoading}
      <p class="alert alert-loading">Loading detail…</p>
    {:else}
      <div class="table-wrap">
        <table>
          <tbody>
            <tr><td>Source</td><td class="mono">{selected.source || '—'}</td></tr>
            <tr><td>State</td><td class="mono">{selected.state}</td></tr>
            <tr><td>Subject</td><td class="mono cell-wrap">{selected.subject || '—'}</td></tr>
            <tr><td>Issuer</td><td class="mono cell-wrap">{selected.issuer || '—'}</td></tr>
            <tr><td>Serial</td><td class="mono">{selected.serial || '—'}</td></tr>
            <tr><td>Fingerprint (SHA-256)</td><td class="mono cell-wrap">{selected.fingerprint_sha256 || '—'}</td></tr>
            <tr><td>Not before</td><td class="mono">{selected.not_before || '—'}</td></tr>
            <tr><td>Not after</td><td class="mono">{selected.not_after || '—'}</td></tr>
            <tr><td>Days left</td><td class={daysClass(selected.days_left)}>{selected.days_left ?? '—'}</td></tr>
            <tr><td>DNS names</td><td class="mono cell-wrap">{(selected.dns_names ?? []).join(', ') || '—'}</td></tr>
            <tr><td>Last error</td><td class="muted cell-wrap">{selected.last_error || '—'}</td></tr>
          </tbody>
        </table>
      </div>
    {/if}
  </div>
{/if}

<ConfirmDialog
  open={confirmDelete !== null}
  title="Delete certificate"
  message={`Remove the certificate for ${confirmDelete ?? ''}?`}
  confirmLabel="Delete"
  danger={true}
  onconfirm={doDelete}
  oncancel={() => (confirmDelete = null)}
/>
