<script lang="ts">
  import { onMount } from 'svelte'
  import { base } from '$app/paths'
  import { api, APIError, normalizeSafeConfig, type ConfigView, type SafeConfig } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canWriteConfig } from '$lib/rbac'

  let view = $state<ConfigView | null>(null)
  let form = $state<SafeConfig | null>(null)
  let proxiesText = $state('')
  let loading = $state(true)
  let error = $state('')
  let saving = $state(false)
  let exporting = $state(false)

  const canWrite = $derived(canWriteConfig(auth.role))

  function applyLive(res: ConfigView) {
    view = res
    const live = res?.live ?? (res as unknown as { Live?: SafeConfig })?.Live
    form = normalizeSafeConfig(live)
    proxiesText = (form.trust.trusted_proxies ?? []).join('\n')
  }

  async function load() {
    loading = true
    try {
      const res = await api.config.get()
      applyLive(res)
      if (!res || (res.live == null && !(res as unknown as { Live?: unknown }).Live)) {
        toast.info('Loaded default live settings (API returned an empty live block)')
      }
      error = ''
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load config'
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
      form.trust.trusted_proxies = proxiesText
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean)
      view = await api.config.update(form)
      applyLive(view)
      toast.info('Configuration updated')
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to save config')
    } finally {
      saving = false
    }
  }

  async function exportJSON() {
    exporting = true
    try {
      await api.config.export()
      toast.info('Config JSON downloaded')
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'export failed')
    } finally {
      exporting = false
    }
  }

  function restartEntries(): Array<[string, string]> {
    if (!view) return []
    const raw = view.restart_required ?? (view as unknown as { RestartRequired?: Record<string, unknown> }).RestartRequired ?? {}
    return Object.entries(raw).map(([k, v]) => {
      try {
        return [k, typeof v === 'string' ? v : JSON.stringify(v)]
      } catch {
        return [k, String(v)]
      }
    })
  }

  onMount(load)
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Config</h1>
    <p class="page-sub">Live-editable guard settings</p>
  </div>
  <div class="actions-row">
    <button type="button" class="btn" onclick={exportJSON} disabled={exporting || loading}>
      {exporting ? 'Exporting…' : 'Export JSON'}
    </button>
  </div>
</div>

{#if loading}
  <p class="alert alert-loading">Loading config…</p>
{:else if error}
  <p class="alert alert-error">{error}</p>
{:else if form}
  <form onsubmit={save}>
    <fieldset>
      <legend>Deployment</legend>
      <p class="page-sub">
        Edge terminates client connections on RavenGuard. Use it when this process is the public listener.
        Behind proxy trusts hop-by-hop headers only from listed proxies. Branding is on
        <a href={`${base}/appearance`}>Appearance</a>.
      </p>
      <div class="field">
        <label for="tr-mode">Trust mode</label>
        <select id="tr-mode" bind:value={form.trust.mode} disabled={!canWrite}>
          <option value="edge">edge</option>
          <option value="behind_proxy">behind_proxy</option>
        </select>
      </div>
      <div class="field">
        <label for="tr-proxies">Trusted proxies</label>
        <textarea
          id="tr-proxies"
          rows="3"
          bind:value={proxiesText}
          disabled={!canWrite}
          placeholder="10.0.0.1/32"
        ></textarea>
        <p class="field-help">One CIDR or address per line, or comma-separated. Required when mode is behind_proxy.</p>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="tr-real-ip">Real IP header</label>
          <input id="tr-real-ip" type="text" bind:value={form.trust.real_ip_header} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="tr-proto">Proto header</label>
          <input id="tr-proto" type="text" bind:value={form.trust.proto_header} disabled={!canWrite} />
        </div>
      </div>
      <div class="field checkbox-field">
        <input id="tr-proxy-protocol" type="checkbox" bind:checked={form.trust.proxy_protocol} disabled={!canWrite} />
        <label for="tr-proxy-protocol">PROXY protocol</label>
      </div>
      <p class="field-help">Restart required for PROXY protocol</p>
    </fieldset>

    <fieldset>
      <legend>Rate limit</legend>
      <div class="field checkbox-field">
        <input id="rl-enabled" type="checkbox" bind:checked={form.ratelimit.enabled} disabled={!canWrite} />
        <label for="rl-enabled">Enabled</label>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="rl-requests">Requests</label>
          <input
            id="rl-requests"
            type="number"
            min="1"
            bind:value={form.ratelimit.requests}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="rl-window">Window</label>
          <input id="rl-window" type="text" bind:value={form.ratelimit.window} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="rl-burst">Burst</label>
          <input id="rl-burst" type="number" min="0" bind:value={form.ratelimit.burst} disabled={!canWrite} />
        </div>
      </div>
      <div class="field checkbox-field">
        <input id="rl-per-path" type="checkbox" bind:checked={form.ratelimit.per_path} disabled={!canWrite} />
        <label for="rl-per-path">Per path</label>
      </div>
      <div class="field checkbox-field">
        <input
          id="rl-challenge-over"
          type="checkbox"
          bind:checked={form.ratelimit.challenge_over}
          disabled={!canWrite}
        />
        <label for="rl-challenge-over">Challenge instead of block when over limit</label>
      </div>
    </fieldset>

    <fieldset>
      <legend>Protect</legend>
      <div class="field checkbox-field">
        <input id="pr-enabled" type="checkbox" bind:checked={form.protect.enabled} disabled={!canWrite} />
        <label for="pr-enabled">Enabled</label>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="pr-max-body">Max body bytes</label>
          <input
            id="pr-max-body"
            type="number"
            min="0"
            bind:value={form.protect.max_body_bytes}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="pr-max-header">Max header bytes</label>
          <input
            id="pr-max-header"
            type="number"
            min="0"
            bind:value={form.protect.max_header_bytes}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="pr-max-url">Max URL bytes</label>
          <input
            id="pr-max-url"
            type="number"
            min="0"
            bind:value={form.protect.max_url_bytes}
            disabled={!canWrite}
          />
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="pr-conc-global">Max concurrency (global)</label>
          <input
            id="pr-conc-global"
            type="number"
            min="0"
            bind:value={form.protect.max_concurrent_global}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="pr-conc-client">Max concurrency (per client)</label>
          <input
            id="pr-conc-client"
            type="number"
            min="0"
            bind:value={form.protect.max_concurrent_per_client}
            disabled={!canWrite}
          />
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="pr-ban-strikes">Ban after strikes</label>
          <input
            id="pr-ban-strikes"
            type="number"
            min="0"
            bind:value={form.protect.ban_after_strikes}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="pr-ban-ttl">Ban TTL</label>
          <input id="pr-ban-ttl" type="text" bind:value={form.protect.ban_ttl} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="pr-write-cost">Write method cost</label>
          <input
            id="pr-write-cost"
            type="number"
            min="0"
            bind:value={form.protect.write_method_cost}
            disabled={!canWrite}
          />
        </div>
      </div>
      <div class="field checkbox-field">
        <input id="pr-attack-block" type="checkbox" bind:checked={form.protect.attack_block} disabled={!canWrite} />
        <label for="pr-attack-block">Block on attack score</label>
      </div>
      <div class="field">
        <label for="pr-attack-score">Attack score threshold</label>
        <input
          id="pr-attack-score"
          type="number"
          min="0"
          bind:value={form.protect.attack_score}
          disabled={!canWrite}
        />
      </div>
    </fieldset>

    <fieldset>
      <legend>Coraza</legend>
      <div class="field checkbox-field">
        <input id="cz-enabled" type="checkbox" bind:checked={form.coraza.enabled} disabled={!canWrite} />
        <label for="cz-enabled">Enabled (rules load requires restart)</label>
      </div>
      {#if form.coraza.enabled && form.coraza.loaded === false}
        <p class="hint">Rules are not loaded yet. Save config with Coraza enabled and restart the process.</p>
      {/if}
      <div class="field-row">
        <div class="field">
          <label for="cz-mode">Mode</label>
          <select id="cz-mode" bind:value={form.coraza.mode} disabled={!canWrite}>
            <option value="block">block</option>
            <option value="detect">detect</option>
          </select>
        </div>
        <div class="field">
          <label for="cz-paranoia">Paranoia</label>
          <input
            id="cz-paranoia"
            type="number"
            min="1"
            max="4"
            bind:value={form.coraza.paranoia}
            disabled={!canWrite}
          />
        </div>
      </div>
    </fieldset>

    <fieldset>
      <legend>Semantic</legend>
      <div class="field checkbox-field">
        <input id="sem-enabled" type="checkbox" bind:checked={form.semantic.enabled} disabled={!canWrite} />
        <label for="sem-enabled">Enabled</label>
      </div>
      <div class="field">
        <label for="sem-mode">Mode</label>
        <select id="sem-mode" bind:value={form.semantic.mode} disabled={!canWrite}>
          <option value="shadow">shadow</option>
          <option value="challenge">challenge</option>
          <option value="block">block</option>
        </select>
      </div>
    </fieldset>

    <fieldset>
      <legend>ML</legend>
      <div class="field checkbox-field">
        <input id="ml-enabled" type="checkbox" bind:checked={form.ml.enabled} disabled={!canWrite} />
        <label for="ml-enabled">Enabled</label>
      </div>
      <div class="field">
        <label for="ml-mode">Mode</label>
        <select id="ml-mode" bind:value={form.ml.mode} disabled={!canWrite}>
          <option value="off">off</option>
          <option value="shadow">shadow</option>
          <option value="challenge">challenge</option>
          <option value="block">block</option>
        </select>
      </div>
      {#if (form.ml.mode === 'challenge' || form.ml.mode === 'block') && !form.ml.attest_ok}
        <p class="hint">Model attestation failed. Challenge and block modes will not enforce until attestation succeeds.</p>
      {/if}
      <div class="field-row">
        <div class="field">
          <label for="ml-challenge-prob">Challenge probability</label>
          <input
            id="ml-challenge-prob"
            type="number"
            min="0"
            max="1"
            step="0.01"
            bind:value={form.ml.challenge_prob}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="ml-block-prob">Block probability</label>
          <input
            id="ml-block-prob"
            type="number"
            min="0"
            max="1"
            step="0.01"
            bind:value={form.ml.block_prob}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="ml-confidence-min">Confidence min</label>
          <input
            id="ml-confidence-min"
            type="number"
            min="0"
            max="1"
            step="0.01"
            bind:value={form.ml.confidence_min}
            disabled={!canWrite}
          />
        </div>
      </div>
    </fieldset>

    <fieldset>
      <legend>Detect</legend>
      <div class="field checkbox-field">
        <input id="dt-enabled" type="checkbox" bind:checked={form.detect.enabled} disabled={!canWrite} />
        <label for="dt-enabled">Enabled</label>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="dt-challenge-score">Challenge score</label>
          <input
            id="dt-challenge-score"
            type="number"
            min="0"
            bind:value={form.detect.challenge_score}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="dt-block-score">Block score</label>
          <input
            id="dt-block-score"
            type="number"
            min="0"
            bind:value={form.detect.block_score}
            disabled={!canWrite}
          />
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="dt-missing-ua">Missing UA</label>
          <input
            id="dt-missing-ua"
            type="number"
            min="0"
            bind:value={form.detect.missing_ua_score}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="dt-scanner-ua">Scanner UA</label>
          <input
            id="dt-scanner-ua"
            type="number"
            min="0"
            bind:value={form.detect.scanner_ua_score}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="dt-ai-ua">AI UA</label>
          <input id="dt-ai-ua" type="number" min="0" bind:value={form.detect.ai_ua_score} disabled={!canWrite} />
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="dt-probe">Probe path</label>
          <input
            id="dt-probe"
            type="number"
            min="0"
            bind:value={form.detect.probe_path_score}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="dt-odd-method">Odd method</label>
          <input
            id="dt-odd-method"
            type="number"
            min="0"
            bind:value={form.detect.odd_method_score}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="dt-missing-accept">Missing Accept</label>
          <input
            id="dt-missing-accept"
            type="number"
            min="0"
            bind:value={form.detect.missing_accept_score}
            disabled={!canWrite}
          />
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="dt-missing-lang">Missing Accept-Language</label>
          <input
            id="dt-missing-lang"
            type="number"
            min="0"
            bind:value={form.detect.missing_accept_lang_score}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="dt-missing-sec">Missing Sec-Fetch</label>
          <input
            id="dt-missing-sec"
            type="number"
            min="0"
            bind:value={form.detect.missing_sec_fetch_score}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="dt-sec-ch">Sec-CH-UA mismatch</label>
          <input
            id="dt-sec-ch"
            type="number"
            min="0"
            bind:value={form.detect.sec_ch_ua_mismatch_score}
            disabled={!canWrite}
          />
        </div>
      </div>
      <div class="field">
        <label for="dt-star-accept">Star Accept browser</label>
        <input
          id="dt-star-accept"
          type="number"
          min="0"
          bind:value={form.detect.star_accept_browser_score}
          disabled={!canWrite}
        />
      </div>
      <div class="field-row">
        <div class="field">
          <label for="dt-404-threshold">404 threshold</label>
          <input
            id="dt-404-threshold"
            type="number"
            min="0"
            bind:value={form.detect.high_404_threshold}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="dt-404-window">404 window</label>
          <input id="dt-404-window" type="text" bind:value={form.detect.high_404_window} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="dt-404-action">404 action</label>
          <select id="dt-404-action" bind:value={form.detect.high_404_action} disabled={!canWrite}>
            <option value="challenge">challenge</option>
            <option value="block">block</option>
            <option value="off">off</option>
          </select>
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="dt-behavior-window">Behavior window</label>
          <input
            id="dt-behavior-window"
            type="text"
            bind:value={form.detect.behavior_window}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="dt-burst-limit">Burst limit</label>
          <input
            id="dt-burst-limit"
            type="number"
            min="0"
            bind:value={form.detect.behavior_burst_limit}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="dt-burst-score">Burst score</label>
          <input
            id="dt-burst-score"
            type="number"
            min="0"
            bind:value={form.detect.behavior_burst_score}
            disabled={!canWrite}
          />
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="dt-fanout">Path fanout limit</label>
          <input
            id="dt-fanout"
            type="number"
            min="0"
            bind:value={form.detect.behavior_path_fanout}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="dt-fanout-score">Path fanout score</label>
          <input
            id="dt-fanout-score"
            type="number"
            min="0"
            bind:value={form.detect.behavior_path_fanout_score}
            disabled={!canWrite}
          />
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="dt-strike-limit">Strike limit</label>
          <input
            id="dt-strike-limit"
            type="number"
            min="0"
            bind:value={form.detect.behavior_strike_limit}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="dt-strike-score">Strike score</label>
          <input
            id="dt-strike-score"
            type="number"
            min="0"
            bind:value={form.detect.behavior_strike_score}
            disabled={!canWrite}
          />
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="dt-bot-header">Bot score header</label>
          <input
            id="dt-bot-header"
            type="text"
            bind:value={form.detect.proxy_signals.bot_score_header}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="dt-bot-header-2">Bot score header 2</label>
          <input
            id="dt-bot-header-2"
            type="text"
            bind:value={form.detect.proxy_signals.bot_score_header_2}
            disabled={!canWrite}
          />
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="dt-ja4">JA4 header</label>
          <input
            id="dt-ja4"
            type="text"
            bind:value={form.detect.proxy_signals.ja4_header}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="dt-low-score">Low score points</label>
          <input
            id="dt-low-score"
            type="number"
            min="0"
            bind:value={form.detect.proxy_signals.low_score_points}
            disabled={!canWrite}
          />
        </div>
      </div>
    </fieldset>

    <fieldset>
      <legend>Challenge</legend>
      <div class="field checkbox-field">
        <input id="ch-enabled" type="checkbox" bind:checked={form.challenge.enabled} disabled={!canWrite} />
        <label for="ch-enabled">Enabled</label>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="ch-mode">Mode</label>
          <select id="ch-mode" bind:value={form.challenge.mode} disabled={!canWrite}>
            <option value="detect">detect</option>
            <option value="always">always</option>
            <option value="attack">attack</option>
          </select>
          <p class="field-help">attack forces the visible checkbox gate for every request</p>
        </div>
        <div class="field">
          <label for="ch-algo">Algorithm</label>
          <select id="ch-algo" bind:value={form.challenge.algorithm} disabled={!canWrite}>
            <option value="adaptive">adaptive</option>
            <option value="sha256">sha256</option>
            <option value="pbkdf2">pbkdf2</option>
            <option value="argon2id">argon2id</option>
          </select>
        </div>
        <div class="field">
          <label for="ch-difficulty">Difficulty</label>
          <input
            id="ch-difficulty"
            type="number"
            min="0"
            max="28"
            bind:value={form.challenge.difficulty}
            disabled={!canWrite}
          />
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="ch-cookie-name">Cookie name</label>
          <input id="ch-cookie-name" type="text" bind:value={form.challenge.cookie_name} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="ch-cookie-ttl">Cookie TTL</label>
          <input id="ch-cookie-ttl" type="text" bind:value={form.challenge.cookie_ttl} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="ch-path-prefix">Path prefix</label>
          <input id="ch-path-prefix" type="text" bind:value={form.challenge.path_prefix} disabled={!canWrite} />
        </div>
      </div>
      <p class="field-help">Restart required to remount challenge routes after changing path prefix</p>
      <div class="field checkbox-field">
        <input
          id="ch-captcha"
          type="checkbox"
          bind:checked={form.challenge.captcha_enabled}
          disabled={!canWrite}
        />
        <label for="ch-captcha">Captcha enabled</label>
      </div>
      <div class="field">
        <label for="ch-captcha-provider">Captcha provider</label>
        <select id="ch-captcha-provider" bind:value={form.challenge.captcha_provider} disabled={!canWrite}>
          <option value="">none</option>
          <option value="stub">stub</option>
          <option value="ravenguard">ravenguard</option>
        </select>
      </div>
    </fieldset>

    <fieldset>
      <legend>Stealth</legend>
      <div class="field-row">
        <div class="field">
          <label for="st-ray">Ray header</label>
          <input id="st-ray" type="text" bind:value={form.stealth.ray_header} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="st-element">Element name</label>
          <input id="st-element" type="text" bind:value={form.stealth.element_name} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="st-bootstrap">Bootstrap global</label>
          <input id="st-bootstrap" type="text" bind:value={form.stealth.bootstrap_global} disabled={!canWrite} />
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="st-access-cookie">Access cookie name</label>
          <input
            id="st-access-cookie"
            type="text"
            bind:value={form.stealth.access_cookie_name}
            disabled={!canWrite}
          />
        </div>
        <div class="field">
          <label for="st-widget">Widget input name</label>
          <input id="st-widget" type="text" bind:value={form.stealth.widget_input_name} disabled={!canWrite} />
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
      <div class="field checkbox-field">
        <input id="st-generic" type="checkbox" bind:checked={form.stealth.generic_copy} disabled={!canWrite} />
        <label for="st-generic">Generic copy</label>
      </div>
      <div class="field checkbox-field">
        <input
          id="st-manifest"
          type="checkbox"
          bind:checked={form.stealth.serve_manifest}
          disabled={!canWrite}
        />
        <label for="st-manifest">Serve manifest</label>
      </div>
      <div class="field checkbox-field">
        <input
          id="st-root-icons"
          type="checkbox"
          bind:checked={form.stealth.serve_root_icons}
          disabled={!canWrite}
        />
        <label for="st-root-icons">Serve root icons</label>
      </div>
    </fieldset>

    <fieldset>
      <legend>Privacy</legend>
      <div class="field checkbox-field">
        <input
          id="pv-hash-ip"
          type="checkbox"
          bind:checked={form.privacy.hash_client_ip}
          disabled={!canWrite}
        />
        <label for="pv-hash-ip">Hash client IP</label>
      </div>
      <div class="field-row">
        <div class="field">
          <label for="pv-log-ip">Log IP</label>
          <select id="pv-log-ip" bind:value={form.privacy.log_ip} disabled={!canWrite}>
            <option value="off">off</option>
            <option value="hash">hash</option>
            <option value="full">full</option>
          </select>
        </div>
        <div class="field">
          <label for="pv-retention">Retention</label>
          <input id="pv-retention" type="text" bind:value={form.privacy.retention} disabled={!canWrite} />
        </div>
        <div class="field">
          <label for="pv-notice">Privacy notice URL</label>
          <input
            id="pv-notice"
            type="text"
            bind:value={form.privacy.privacy_notice_url}
            disabled={!canWrite}
          />
        </div>
      </div>
    </fieldset>

    <fieldset>
      <legend>Logging</legend>
      <div class="field-row">
        <div class="field">
          <label for="lg-level">Level</label>
          <select id="lg-level" bind:value={form.logging.level} disabled={!canWrite}>
            <option value="debug">debug</option>
            <option value="info">info</option>
            <option value="warn">warn</option>
            <option value="error">error</option>
          </select>
        </div>
        <div class="field">
          <label for="lg-format">Format</label>
          <select id="lg-format" bind:value={form.logging.format} disabled={!canWrite}>
            <option value="text">text</option>
            <option value="json">json</option>
          </select>
        </div>
      </div>
    </fieldset>

    {#if canWrite}
      <button type="submit" class="btn btn-primary" disabled={saving}>
        {saving ? 'Saving…' : 'Save changes'}
      </button>
    {/if}
  </form>

  <div class="section">
    <div class="section-title">Restart required</div>
    <p class="page-sub">These settings are fixed at process start and cannot be changed from this console.</p>
    <div class="table-wrap">
      <table>
        <tbody>
          {#each restartEntries() as [key, value] (key)}
            <tr>
              <td class="mono cell-clip">{key}</td>
              <td class="mono muted cell-wrap">{value}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>
{/if}
