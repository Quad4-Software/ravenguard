<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import { api, APIError, normalizeSafeConfig, type SafeConfig } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canWriteConfig } from '$lib/rbac'

  const previewPages = ['challenge', 'block', 'ratelimit', 'upstream', 'error', 'access'] as const
  const maxAssetBytes = 512 * 1024

  let form = $state<SafeConfig | null>(null)
  let loading = $state(true)
  let error = $state('')
  let saving = $state(false)
  let previewing = $state(false)
  let previewPage = $state<(typeof previewPages)[number]>('challenge')
  let previewHTML = $state('')
  let logoObjectURL = $state('')
  let faviconObjectURL = $state('')
  let uploading = $state<'logo' | 'favicon' | ''>('')

  const canWrite = $derived(canWriteConfig(auth.role))

  function colorValue(v: string, fallback: string) {
    return /^#[0-9a-fA-F]{6}$/.test(v) ? v : fallback
  }

  function revokeURL(url: string) {
    if (url) URL.revokeObjectURL(url)
  }

  async function load() {
    loading = true
    try {
      const res = await api.config.get()
      form = normalizeSafeConfig(res.live)
      error = ''
      await refreshPreview()
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load appearance'
      form = null
    } finally {
      loading = false
    }
  }

  async function save(event: SubmitEvent) {
    event.preventDefault()
    if (!form) return
    saving = true
    try {
      const view = await api.config.update(form)
      form = normalizeSafeConfig(view.live)
      toast.info('Appearance saved')
      await refreshPreview()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to save appearance')
    } finally {
      saving = false
    }
  }

  async function refreshPreview() {
    if (!form) return
    previewing = true
    try {
      previewHTML = await api.appearance.preview(previewPage, form)
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'preview failed')
    } finally {
      previewing = false
    }
  }

  async function setPreviewPage(page: (typeof previewPages)[number]) {
    previewPage = page
    await refreshPreview()
  }

  async function uploadAsset(kind: 'logo' | 'favicon', list: FileList | null) {
    if (!form || !list || list.length === 0) return
    const file = list[0]
    if (file.size > maxAssetBytes) {
      toast.error('file too large (max 512KB)')
      return
    }
    uploading = kind
    try {
      const res = await api.appearance.upload(kind, file)
      if (kind === 'logo') {
        revokeURL(logoObjectURL)
        logoObjectURL = URL.createObjectURL(file)
        form.ui.logo_url = res.url
      } else {
        revokeURL(faviconObjectURL)
        faviconObjectURL = URL.createObjectURL(file)
        form.ui.favicon_url = res.url
      }
      toast.info(`${kind} uploaded`)
      await refreshPreview()
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'upload failed')
    } finally {
      uploading = ''
    }
  }

  onMount(load)
  onDestroy(() => {
    revokeURL(logoObjectURL)
    revokeURL(faviconObjectURL)
  })
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Appearance</h1>
    <p class="page-sub">Public challenge and status page branding</p>
  </div>
</div>

{#if loading}
  <p class="alert alert-loading">Loading appearance…</p>
{:else if error}
  <p class="alert alert-error">{error}</p>
{:else if form}
  <form onsubmit={save}>
    <fieldset>
      <legend>Brand</legend>
      <div class="field-row">
        <div class="field">
          <label for="ui-brand">Brand</label>
          <input id="ui-brand" type="text" bind:value={form.ui.brand} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="ui-lang">Language</label>
          <input id="ui-lang" type="text" bind:value={form.ui.lang} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="ui-ray-label">Ray label</label>
          <input id="ui-ray-label" type="text" bind:value={form.ui.ray_label} disabled={!canWrite} />
        </div>
      </div>
      <div class="field">
        <label for="ui-status-text">Status text</label>
        <input id="ui-status-text" type="text" bind:value={form.ui.status_text} disabled={!canWrite} />
      </div>
      <div class="field">
        <label for="ui-description">Description</label>
        <input id="ui-description" type="text" bind:value={form.ui.description} disabled={!canWrite} />
      </div>
      <div class="field-row">
        <div class="field">
          <label for="ui-footer">Footer text</label>
          <input id="ui-footer" type="text" bind:value={form.ui.footer_text} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="ui-robots">Robots</label>
          <input id="ui-robots" type="text" bind:value={form.ui.robots} disabled={!canWrite} />
        </div>
      </div>
      <div class="field checkbox-field">
        <input
          id="st-hide-brand"
          type="checkbox"
          bind:checked={form.stealth.hide_brand_mark}
          disabled={!canWrite}
        />
        <label for="st-hide-brand">Hide brand mark</label>
      </div>
    </fieldset>

    <fieldset>
      <legend>Copy</legend>
      <div class="field-row">
        <div class="field">
          <label for="ui-challenge-title">Challenge title</label>
          <input id="ui-challenge-title" type="text" bind:value={form.ui.challenge_title} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="ui-block-title">Block title</label>
          <input id="ui-block-title" type="text" bind:value={form.ui.block_title} disabled={!canWrite} />
        </div>
      </div>
      <div class="field">
        <label for="ui-challenge-sub">Challenge subtitle</label>
        <input id="ui-challenge-sub" type="text" bind:value={form.ui.challenge_subtitle} disabled={!canWrite} />
      </div>
      <div class="field-row">
        <div class="field">
          <label for="ui-rate-title">Rate limit title</label>
          <input id="ui-rate-title" type="text" bind:value={form.ui.rate_limit_title} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="ui-upstream-title">Upstream title</label>
          <input id="ui-upstream-title" type="text" bind:value={form.ui.upstream_title} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="ui-error-title">Error title</label>
          <input id="ui-error-title" type="text" bind:value={form.ui.error_title} disabled={!canWrite} />
        </div>
      </div>
    </fieldset>

    <fieldset>
      <legend>Colors</legend>
      <div class="field-row">
        <div class="field">
          <label for="ui-theme">Theme color</label>
          <div class="color-pair">
            <input
              id="ui-theme-color"
              type="color"
              value={colorValue(form.ui.theme_color, '#050505')}
              disabled={!canWrite}
              oninput={(e) => {
                if (form) form.ui.theme_color = e.currentTarget.value
              }}
            />
            <input id="ui-theme" type="text" bind:value={form.ui.theme_color} disabled={!canWrite} />
          </div>
        </div>
        <div class="field">
          <label for="ui-bg">Background</label>
          <div class="color-pair">
            <input
              id="ui-bg-color"
              type="color"
              value={colorValue(form.ui.background || form.ui.theme_color, '#050505')}
              disabled={!canWrite}
              oninput={(e) => {
                if (form) form.ui.background = e.currentTarget.value
              }}
            />
            <input id="ui-bg" type="text" bind:value={form.ui.background} disabled={!canWrite} />
          </div>
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="ui-fg">Foreground</label>
          <div class="color-pair">
            <input
              id="ui-fg-color"
              type="color"
              value={colorValue(form.ui.foreground, '#e8e8e8')}
              disabled={!canWrite}
              oninput={(e) => {
                if (form) form.ui.foreground = e.currentTarget.value
              }}
            />
            <input id="ui-fg" type="text" bind:value={form.ui.foreground} disabled={!canWrite} />
          </div>
        </div>
        <div class="field">
          <label for="ui-accent">Accent</label>
          <div class="color-pair">
            <input
              id="ui-accent-color"
              type="color"
              value={colorValue(form.ui.accent, '#c4c4c4')}
              disabled={!canWrite}
              oninput={(e) => {
                if (form) form.ui.accent = e.currentTarget.value
              }}
            />
            <input id="ui-accent" type="text" bind:value={form.ui.accent} disabled={!canWrite} />
          </div>
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="ui-font-sans">Sans font</label>
          <input id="ui-font-sans" type="text" bind:value={form.ui.font_sans} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="ui-font-mono">Mono font</label>
          <input id="ui-font-mono" type="text" bind:value={form.ui.font_mono} disabled={!canWrite} />
        </div>
      </div>
    </fieldset>

    <fieldset>
      <legend>Assets</legend>
      <div class="field-row">
        <div class="field">
          <label for="ui-logo-url">Logo URL</label>
          <input id="ui-logo-url" type="text" bind:value={form.ui.logo_url} disabled={!canWrite} />
          {#if canWrite}
            <input
              id="ui-logo-file"
              type="file"
              accept="image/png,image/jpeg,image/webp,image/x-icon,image/svg+xml,.png,.jpg,.jpeg,.webp,.ico,.svg"
              disabled={uploading !== ''}
              onchange={(e) => uploadAsset('logo', e.currentTarget.files)}
            />
          {/if}
          {#if logoObjectURL || form.ui.logo_url}
            <img class="asset-thumb" src={logoObjectURL || form.ui.logo_url} alt="Logo preview" />
          {/if}
        </div>
        <div class="field">
          <label for="ui-favicon-url">Favicon URL</label>
          <input id="ui-favicon-url" type="text" bind:value={form.ui.favicon_url} disabled={!canWrite} />
          {#if canWrite}
            <input
              id="ui-favicon-file"
              type="file"
              accept="image/png,image/jpeg,image/webp,image/x-icon,image/svg+xml,.png,.jpg,.jpeg,.webp,.ico,.svg"
              disabled={uploading !== ''}
              onchange={(e) => uploadAsset('favicon', e.currentTarget.files)}
            />
          {/if}
          {#if faviconObjectURL || form.ui.favicon_url}
            <img class="asset-thumb" src={faviconObjectURL || form.ui.favicon_url} alt="Favicon preview" />
          {/if}
        </div>
      </div>
      <p class="field-help">PNG, JPEG, WebP, ICO, or SVG. Max 512KB.</p>
      <div class="field-row">
        <div class="field">
          <label for="ui-og">OG image URL</label>
          <input id="ui-og" type="text" bind:value={form.ui.og_image} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="ui-privacy">Privacy notice URL</label>
          <input id="ui-privacy" type="text" bind:value={form.ui.privacy_notice_url} disabled={!canWrite} />
        </div>
      </div>
    </fieldset>

    <fieldset>
      <legend>Custom CSS</legend>
      <div class="field">
        <label for="ui-css">CSS</label>
        <textarea id="ui-css" rows="8" bind:value={form.ui.custom_css} disabled={!canWrite}></textarea>
      </div>
    </fieldset>

    <fieldset>
      <legend>Preview</legend>
      <div class="tab-row" role="tablist">
        {#each previewPages as page (page)}
          <button
            type="button"
            class="tab"
            class:active={previewPage === page}
            role="tab"
            aria-selected={previewPage === page}
            onclick={() => setPreviewPage(page)}
          >
            {page}
          </button>
        {/each}
      </div>
      <div class="actions-row preview-actions">
        <button type="button" class="btn" onclick={refreshPreview} disabled={previewing || !form}>
          {previewing ? 'Rendering…' : 'Refresh preview'}
        </button>
      </div>
      <iframe class="preview-frame" title="Appearance preview" srcdoc={previewHTML}></iframe>
    </fieldset>

    {#if canWrite}
      <button type="submit" class="btn btn-primary" disabled={saving}>
        {saving ? 'Saving…' : 'Save changes'}
      </button>
    {/if}
  </form>
{/if}

<style>
  .preview-actions {
    justify-content: flex-start;
    margin-bottom: 0.75rem;
  }

  .preview-frame {
    display: block;
    width: 100%;
    height: 28rem;
    border: 1px solid var(--line);
    background: #111;
    margin-bottom: 1rem;
  }

  .asset-thumb {
    display: block;
    max-height: 4rem;
    max-width: 10rem;
    margin-top: 0.5rem;
    object-fit: contain;
  }
</style>
