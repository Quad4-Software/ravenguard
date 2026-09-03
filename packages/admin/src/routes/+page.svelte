<script lang="ts">
  import { onMount, onDestroy } from 'svelte'
  import { base } from '$app/paths'
  import { api, APIError, type ModuleKey, type Status, type StatusSample } from '$lib/api'
  import { toast } from '$lib/toast.svelte'
  import { auth } from '$lib/auth.svelte'
  import { canWriteConfig } from '$lib/rbac'
  import Sparkline from '$lib/components/Sparkline.svelte'
  import Gauge from '$lib/components/Gauge.svelte'
  import BarMeter from '$lib/components/BarMeter.svelte'
  import Metric from '$lib/components/Metric.svelte'

  const pollMs = 5000

  let status = $state.raw<Status | null>(null)
  let samples = $state.raw<StatusSample[]>([])
  let loading = $state(true)
  let error = $state('')
  let refreshedAt = $state('')
  let timer: ReturnType<typeof setInterval> | undefined
  let toggling = $state<ModuleKey | null>(null)

  const canWrite = $derived(canWriteConfig(auth.role))

  async function load() {
    if (typeof document !== 'undefined' && document.hidden) return
    try {
      const [st, hist] = await Promise.all([api.status.get(), api.status.history()])
      status = st
      samples = hist.samples ?? []
      refreshedAt = new Date().toLocaleTimeString()
      error = ''
    } catch (err) {
      error = err instanceof APIError ? err.message : 'failed to load status'
    } finally {
      loading = false
    }
  }

  onMount(() => {
    void load()
    timer = setInterval(() => {
      void load()
    }, pollMs)
    document.addEventListener('visibilitychange', handleVisibility)
  })

  onDestroy(() => {
    if (timer) clearInterval(timer)
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', handleVisibility)
    }
  })

  function handleVisibility() {
    if (!document.hidden) void load()
  }

  function formatUptime(seconds: number): string {
    const d = Math.floor(seconds / 86400)
    const h = Math.floor((seconds % 86400) / 3600)
    const m = Math.floor((seconds % 3600) / 60)
    const parts: string[] = []
    if (d) parts.push(`${d}d`)
    if (d || h) parts.push(`${h}h`)
    parts.push(`${m}m`)
    return parts.join(' ')
  }

  function formatBytes(n: number): string {
    if (!Number.isFinite(n) || n < 0) return '0 B'
    const units = ['B', 'KB', 'MB', 'GB', 'TB']
    let v = n
    let i = 0
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024
      i += 1
    }
    const digits = i === 0 ? 0 : v >= 10 ? 1 : 2
    return `${v.toFixed(digits)} ${units[i]}`
  }

  function formatPct(n: number): string {
    if (!Number.isFinite(n)) return '0%'
    const a = Math.abs(n)
    if (a >= 10) return `${n.toFixed(0)}%`
    return `${n.toFixed(1)}%`
  }

  function formatNum(n: number): string {
    if (!Number.isFinite(n)) return '0'
    const sign = n < 0 ? '-' : ''
    const x = Math.abs(n)
    if (x >= 1_000_000_000) return `${sign}${(x / 1_000_000_000).toFixed(1)}B`
    if (x >= 1_000_000) return `${sign}${(x / 1_000_000).toFixed(1)}M`
    if (x >= 10_000) return `${sign}${(x / 1000).toFixed(1)}k`
    return `${sign}${Math.round(x).toLocaleString('en-US')}`
  }

  function formatNs(ns: number): string {
    if (!Number.isFinite(ns) || ns <= 0) return '0 ns'
    if (ns < 1000) return `${Math.round(ns)} ns`
    if (ns < 1_000_000) return `${(ns / 1000).toFixed(1)} us`
    return `${(ns / 1_000_000).toFixed(2)} ms`
  }

  function usageTone(pct: number): 'ok' | 'warn' | 'bad' {
    if (pct >= 85) return 'bad'
    if (pct >= 60) return 'warn'
    return 'ok'
  }

  function series(key: keyof StatusSample): number[] {
    return samples.map((s) => {
      const v = s[key]
      return typeof v === 'number' ? v : 0
    })
  }

  const health = $derived.by(() => {
    const h = status?.upstream_healthy
    if (h === true) return { label: 'healthy', tone: 'ok' as const }
    if (h === false) return { label: 'down', tone: 'bad' as const }
    return { label: 'unknown', tone: 'warn' as const }
  })

  const proc = $derived(status?.process)

  const cpuPct = $derived(proc?.cpu_percent ?? 0)

  const heapPct = $derived.by(() => {
    const p = proc
    if (!p || p.heap_sys_bytes <= 0) return 0
    return (p.heap_alloc_bytes / p.heap_sys_bytes) * 100
  })

  const coverage = $derived.by(() => {
    if (!status) return { items: [] as { label: string; value: number }[], max: 1 }
    const items = [
      { label: 'IP blocklist', value: status.blocklists?.ip_count ?? 0 },
      { label: 'DNS blocklist', value: status.blocklists?.dns_count ?? 0 },
      { label: 'UA blocklist', value: status.blocklists?.ua_count ?? 0 },
      { label: 'Q-Feeds IPs', value: status.qfeeds?.ip_count ?? 0 },
      { label: 'Q-Feeds domains', value: status.qfeeds?.domain_count ?? 0 },
    ]
    const max = Math.max(...items.map((i) => i.value), 1)
    return { items, max }
  })

  const modules = $derived.by(() => {
    if (!status) return []
    const qf = status.qfeeds_enabled ? (status.qfeeds?.failed ? 'degraded' : 'on') : 'off'
    return [
      {
        key: 'protect' as const,
        label: 'Protect',
        state: status.protect_enabled ? 'on' : 'off',
        enabled: !!status.protect_enabled,
        href: `${base}/config`,
      },
      {
        key: 'ratelimit' as const,
        label: 'Rate limit',
        state: status.ratelimit_enabled ? 'on' : 'off',
        enabled: !!status.ratelimit_enabled,
        href: `${base}/config`,
      },
      {
        key: 'detect' as const,
        label: 'Detect',
        state: status.detect_enabled ? 'on' : 'off',
        enabled: !!status.detect_enabled,
        href: `${base}/config`,
      },
      {
        key: 'challenge' as const,
        label: 'Challenge',
        state: status.challenge_enabled ? 'on' : 'off',
        enabled: !!status.challenge_enabled,
        href: `${base}/config`,
      },
      {
        key: 'qfeeds' as const,
        label: 'Q-Feeds',
        state: qf,
        enabled: !!status.qfeeds_enabled,
        href: `${base}/qfeeds`,
      },
    ]
  })

  async function toggleModule(key: ModuleKey, enabled: boolean) {
    if (!canWrite || toggling) return
    toggling = key
    try {
      await api.config.setModuleEnabled(key, enabled)
      await load()
      toast.info(`${key} ${enabled ? 'enabled' : 'disabled'}`)
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'failed to update module')
      await load()
    } finally {
      toggling = null
    }
  }
</script>

<div class="page-head">
  <div>
    <h1 class="page-title">Overview</h1>
    <p class="page-sub">Process load, traffic, and guard coverage</p>
  </div>
</div>

{#if loading}
  <p class="alert alert-loading">Loading status…</p>
{:else if error && !status}
  <p class="alert alert-error">{error}</p>
{/if}

{#if status}
  {#if error}
    <p class="alert alert-error">{error}</p>
  {/if}

  <div class="section">
    <div class="hero">
      <div class="hero-cell">
        <span class={['dot', health.tone, health.tone === 'ok' && 'pulse']}></span>
        <div>
          <div class="hero-k">Upstream</div>
          <div class={['hero-v', health.tone]}>{health.label}</div>
        </div>
      </div>
      <div class="hero-cell">
        <div>
          <div class="hero-k">Uptime</div>
          <div class="hero-v mono">{formatUptime(status.uptime_seconds)}</div>
        </div>
      </div>
      <div class="hero-cell">
        <span class="dot ok pulse"></span>
        <div>
          <div class="hero-k">Live</div>
          <div class="hero-v live-meta">
            {pollMs / 1000}s
            {#if refreshedAt}
              <span class="muted">· {refreshedAt}</span>
            {/if}
          </div>
        </div>
      </div>
    </div>
    <p class="page-sub hero-links">
      <a href={`${base}/certs`}>Certificates</a>
      ·
      <a href={`${base}/logs`}>Live logs</a>
      ·
      <a href={`${base}/routes`}>Routes</a>
    </p>
  </div>

  <div class="section">
    <div class="section-title">Process load</div>
    <div class="process-grid">
      <div class="process-cell">
        <Gauge label="CPU" value={cpuPct} display={formatPct(cpuPct)} tone={usageTone(cpuPct)} />
      </div>
      <div class="process-cell">
        <Gauge
          label="Heap"
          value={heapPct}
          display={formatBytes(proc?.heap_alloc_bytes ?? 0)}
          tone={usageTone(heapPct)}
        />
        <p class="process-note">
          {formatPct(heapPct)} of sys {formatBytes(proc?.heap_sys_bytes ?? 0)}
        </p>
      </div>
      <div class="process-cell process-stat">
        <div class="metric-label">RSS</div>
        <div class="metric-value mono">{formatBytes(proc?.rss_bytes ?? 0)}</div>
        <p class="process-note">Go sys {formatBytes(proc?.sys_bytes ?? 0)}</p>
      </div>
      <div class="process-cell process-stat">
        <div class="metric-label">Goroutines</div>
        <div class="metric-value mono">{formatNum(proc?.goroutines ?? 0)}</div>
        <p class="process-note">
          GOMAXPROCS {proc?.gomaxprocs ?? 0} · {proc?.num_cpu ?? 0} CPU
        </p>
        <p class="process-note">
          GC {formatNum(proc?.num_gc ?? 0)} · pause {formatNs(proc?.gc_pause_ns ?? 0)}
        </p>
      </div>
    </div>
    <div class="chart-grid">
      <Sparkline label="CPU" values={series('cpu_percent')} format={formatPct} height={80} />
      <Sparkline
        label="RSS"
        values={series('rss_bytes')}
        format={formatBytes}
        stroke="var(--warn)"
        height={80}
      />
      <Sparkline label="Heap alloc" values={series('heap_alloc_bytes')} format={formatBytes} height={80} />
      <Sparkline label="Goroutines" values={series('goroutines')} format={formatNum} height={80} />
    </div>
  </div>

  <div class="section">
    <div class="section-title">Traffic · last {samples.length || 1} samples</div>
    <div class="metric-grid">
      <Metric label="In flight" value={formatNum(status.concurrency_global)} />
      <Metric label="Busy clients" value={formatNum(status.concurrency_clients)} />
      <Metric label="Active bans" value={formatNum(status.ban_count)} />
      <Metric label="Rate buckets" value={formatNum(status.ratelimit_buckets)} />
    </div>
    <div class="chart-grid traffic-charts">
      <Sparkline label="Concurrency" values={series('concurrency_global')} format={formatNum} height={72} />
      <Sparkline label="Clients" values={series('concurrency_clients')} format={formatNum} height={72} />
      <Sparkline
        label="Bans"
        values={series('ban_count')}
        format={formatNum}
        stroke="var(--warn)"
        height={72}
      />
      <Sparkline label="Rate buckets" values={series('ratelimit_buckets')} format={formatNum} height={72} />
    </div>
  </div>

  <div class="section">
    <div class="section-title">Coverage</div>
    <div class="meter-list">
      {#each coverage.items as item (item.label)}
        <BarMeter label={item.label} value={item.value} max={coverage.max} display={formatNum(item.value)} />
      {/each}
    </div>
  </div>

  <div class="section">
    <div class="section-title">Modules</div>
    <div class="module-row">
      {#each modules as mod (mod.key)}
        <div class={['module', mod.state]}>
          <span class={['dot', { ok: mod.state === 'on', bad: mod.state === 'degraded' }]}></span>
          <a class="module-label" href={mod.href}>{mod.label}</a>
          <span class="module-state">{mod.state}</span>
          <label class="switch">
            <input
              type="checkbox"
              checked={mod.enabled}
              disabled={!canWrite || toggling === mod.key}
              onchange={(e) => void toggleModule(mod.key, e.currentTarget.checked)}
            />
            <span class="switch-track" aria-hidden="true"></span>
            <span class="sr-only">{mod.enabled ? 'Disable' : 'Enable'} {mod.label}</span>
          </label>
        </div>
      {/each}
    </div>
  </div>
{/if}

<style>
  .hero {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    border-top: 1px solid var(--line);
    border-left: 1px solid var(--line);
  }

  .hero-cell {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 1rem 1.1rem;
    border-right: 1px solid var(--line);
    border-bottom: 1px solid var(--line);
    min-width: 0;
  }

  .hero-k {
    font-family: var(--font-mono);
    font-size: 0.68rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--code);
  }

  .hero-v {
    font-size: 1.15rem;
    font-weight: 500;
    letter-spacing: -0.02em;
    margin-top: 0.15rem;
  }

  .hero-v.ok {
    color: var(--ok);
  }

  .hero-v.warn {
    color: var(--warn);
  }

  .hero-v.bad {
    color: var(--bad);
  }

  .live-meta {
    font-size: 1rem;
    font-family: var(--font-mono);
  }

  .hero-links {
    margin-top: 0.75rem;
  }

  .hero-links a {
    color: var(--muted);
    text-decoration: none;
  }

  .hero-links a:hover {
    color: var(--fg);
  }

  .process-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    border-top: 1px solid var(--line);
    border-left: 1px solid var(--line);
    margin-bottom: 0.75rem;
  }

  .process-cell {
    border-right: 1px solid var(--line);
    border-bottom: 1px solid var(--line);
    min-width: 0;
  }

  .process-stat {
    padding: 1rem 1.1rem 0.85rem;
    display: flex;
    flex-direction: column;
    justify-content: center;
  }

  .process-note {
    margin-top: 0.35rem;
    font-size: 0.75rem;
    color: var(--muted);
    font-family: var(--font-mono);
  }

  .process-cell:not(.process-stat) .process-note {
    text-align: center;
    padding: 0 0.5rem 0.75rem;
    margin-top: 0;
  }

  .traffic-charts {
    margin-top: 0.75rem;
  }

  .meter-list {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
    border-top: 1px solid var(--line);
    border-left: 1px solid var(--line);
  }

  .meter-list :global(.meter) {
    border-right: 1px solid var(--line);
    border-bottom: 1px solid var(--line);
  }

  .module-row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
  }

  .module {
    display: inline-flex;
    align-items: center;
    gap: 0.45rem;
    font-family: var(--font-mono);
    font-size: 0.68rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    padding: 0.4rem 0.65rem;
    border: 1px solid var(--line);
    border-left: 2px solid var(--muted);
    color: var(--muted);
  }

  .module.on {
    color: var(--fg);
    border-left-color: var(--ok);
  }

  .module.off {
    border-left-color: var(--line);
  }

  .module.degraded {
    color: var(--fg);
    border-left-color: var(--bad);
  }

  .module-label {
    color: inherit;
    text-decoration: none;
  }

  .module-label:hover {
    color: var(--fg);
  }

  .module-state {
    color: var(--code);
  }

  .module.on .module-state {
    color: var(--ok);
  }

  .module.degraded .module-state {
    color: var(--bad);
  }

  @media (max-width: 900px) {
    .process-grid {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }

  @media (max-width: 720px) {
    .hero {
      grid-template-columns: 1fr;
    }
  }

  @media (max-width: 520px) {
    .process-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
