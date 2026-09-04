import { base } from '$app/paths'

export type Role = 'owner' | 'admin' | 'viewer'

export interface User {
  id: number
  username: string
  role: Role
  created_at: string
  updated_at: string
  disabled: boolean
}

export interface Session {
  user: User
  csrf_token: string
  token_auth?: boolean
  expires_at?: string
  session_id?: string
}

export interface AuthSession {
  id: string
  ip: string
  user_agent: string
  created_at: string
  expires_at: string
  current: boolean
}

export type ModuleKey = 'protect' | 'ratelimit' | 'detect' | 'challenge' | 'qfeeds'

export interface APIToken {
  id: string
  user_id: number
  name: string
  role: Role
  created_at: string
  expires_at?: string
  last_used_at?: string
  revoked: boolean
}

export interface AuditEvent {
  id: number
  created_at: string
  actor_id?: number
  actor_name: string
  action: string
  target: string
  detail: string
  ip: string
}

export interface BlocklistStats {
  ip_count: number
  dns_count: number
  ua_count: number
  last_reload?: string
  overlay_dir?: string
  ip_files?: string[]
  dns_files?: string[]
  ua_files?: string[]
}

export interface QFeedsStatus {
  enabled: boolean
  failed: boolean
  ip_count: number
  domain_count: number
  feeds: string[]
  refresh: string
  on_error: string
  base_url: string
  has_token: boolean
  limit: number
}

export interface QFeedsSafe {
  enabled: boolean
  feeds: string[]
  refresh: string
  on_error: string
  base_url: string
  limit: number
  api_token?: string
}

export interface ProcessStats {
  cpu_percent: number
  goroutines: number
  gomaxprocs: number
  num_cpu: number
  heap_alloc_bytes: number
  heap_sys_bytes: number
  sys_bytes: number
  rss_bytes: number
  gc_pause_ns: number
  num_gc: number
}

export interface Status {
  uptime_seconds: number
  upstream_healthy: boolean | null
  ban_count: number
  concurrency_global: number
  concurrency_clients: number
  ratelimit_buckets: number
  blocklists: BlocklistStats
  challenge_enabled: boolean
  qfeeds_enabled: boolean
  qfeeds: QFeedsStatus
  protect_enabled: boolean
  ratelimit_enabled: boolean
  detect_enabled: boolean
  version: string
  commit: string
  process: ProcessStats
}

export interface StatusSample {
  at: string
  ban_count: number
  concurrency_global: number
  concurrency_clients: number
  ratelimit_buckets: number
  upstream_healthy: boolean | null
  cpu_percent: number
  rss_bytes: number
  heap_alloc_bytes: number
  goroutines: number
}

export interface Ban {
  key: string
  strikes: number
  banned_until?: string
  window_start?: string
  active: boolean
}

export interface RateLimitSafe {
  enabled: boolean
  requests: number
  window: string
  burst: number
  per_path: boolean
  challenge_over: boolean
}

export interface ProtectSafe {
  enabled: boolean
  max_body_bytes: number
  max_header_bytes: number
  max_url_bytes: number
  max_concurrent_global: number
  max_concurrent_per_client: number
  ban_after_strikes: number
  ban_ttl: string
  attack_block: boolean
  attack_score: number
  write_method_cost: number
}

export interface DetectSafe {
  enabled: boolean
  challenge_score: number
  block_score: number
  missing_ua_score: number
  scanner_ua_score: number
  ai_ua_score: number
  probe_path_score: number
  odd_method_score: number
  missing_accept_score: number
  missing_accept_lang_score: number
  missing_sec_fetch_score: number
  sec_ch_ua_mismatch_score: number
  star_accept_browser_score: number
  high_404_threshold: number
  high_404_window: string
  high_404_action: string
  behavior_window: string
  behavior_burst_limit: number
  behavior_burst_score: number
  behavior_path_fanout: number
  behavior_path_fanout_score: number
  behavior_strike_limit: number
  behavior_strike_score: number
  proxy_signals: ProxySignalsSafe
}

export interface ProxySignalsSafe {
  bot_score_header: string
  bot_score_header_2: string
  ja4_header: string
  low_score_points: number
}

export interface ChallengeSafe {
  enabled: boolean
  mode: string
  difficulty: number
  algorithm: string
  cookie_name: string
  cookie_ttl: string
  path_prefix: string
  captcha_enabled: boolean
  captcha_provider: string
}

export interface TrustSafe {
  mode: string
  trusted_proxies: string[]
  real_ip_header: string
  proto_header: string
  proxy_protocol: boolean
}

export interface UISafe {
  brand: string
  status_text: string
  logo_url: string
  favicon_url: string
  theme_color: string
  background: string
  foreground: string
  accent: string
  font_sans: string
  font_mono: string
  challenge_title: string
  challenge_subtitle: string
  block_title: string
  rate_limit_title: string
  upstream_title: string
  error_title: string
  footer_text: string
  contact: string
  custom_css: string
  description: string
  lang: string
  robots: string
  privacy_notice_url: string
  og_image: string
  ray_label: string
}

export interface StealthSafe {
  ray_header: string
  element_name: string
  bootstrap_global: string
  access_cookie_name: string
  hide_brand_mark: boolean
  generic_copy: boolean
  serve_manifest: boolean
  serve_root_icons: boolean
  widget_input_name: string
}

export interface PrivacySafe {
  hash_client_ip: boolean
  log_ip: string
  retention: string
  privacy_notice_url: string
}

export interface LoggingSafe {
  level: string
  format: string
}

export interface SafeConfig {
  ratelimit: RateLimitSafe
  protect: ProtectSafe
  detect: DetectSafe
  coraza: CorazaSafe
  challenge: ChallengeSafe
  ui: UISafe
  trust: TrustSafe
  stealth: StealthSafe
  privacy: PrivacySafe
  logging: LoggingSafe
  qfeeds?: QFeedsSafe
}

export interface CorazaSafe {
  enabled: boolean
  loaded?: boolean
  mode: string
  paranoia: number
}

export interface ConfigView {
  live: SafeConfig
  restart_required: Record<string, unknown>
}

/** Fills missing nested live config so the form never binds to undefined. */
export function normalizeSafeConfig(raw: Partial<SafeConfig> | null | undefined): SafeConfig {
  const r = raw ?? {}
  const rl = r.ratelimit ?? ({} as Partial<RateLimitSafe>)
  const pr = r.protect ?? ({} as Partial<ProtectSafe>)
  const dt = r.detect ?? ({} as Partial<DetectSafe>)
  const cz = r.coraza ?? ({} as Partial<CorazaSafe>)
  const ps = dt.proxy_signals ?? ({} as Partial<ProxySignalsSafe>)
  const ch = r.challenge ?? ({} as Partial<ChallengeSafe>)
  const ui = r.ui ?? ({} as Partial<UISafe>)
  const tr = r.trust ?? ({} as Partial<TrustSafe>)
  const st = r.stealth ?? ({} as Partial<StealthSafe>)
  const pv = r.privacy ?? ({} as Partial<PrivacySafe>)
  const lg = r.logging ?? ({} as Partial<LoggingSafe>)
  const qf = r.qfeeds
  const out: SafeConfig = {
    ratelimit: {
      enabled: !!rl.enabled,
      requests: Number(rl.requests ?? 120),
      window: String(rl.window ?? '1m'),
      burst: Number(rl.burst ?? 60),
      per_path: !!rl.per_path,
      challenge_over: rl.challenge_over !== false,
    },
    protect: {
      enabled: pr.enabled !== false,
      max_body_bytes: Number(pr.max_body_bytes ?? 1048576),
      max_header_bytes: Number(pr.max_header_bytes ?? 16384),
      max_url_bytes: Number(pr.max_url_bytes ?? 8192),
      max_concurrent_global: Number(pr.max_concurrent_global ?? 8192),
      max_concurrent_per_client: Number(pr.max_concurrent_per_client ?? 32),
      ban_after_strikes: Number(pr.ban_after_strikes ?? 5),
      ban_ttl: String(pr.ban_ttl ?? '10m'),
      attack_block: pr.attack_block !== false,
      attack_score: Number(pr.attack_score ?? 90),
      write_method_cost: Number(pr.write_method_cost ?? 3),
    },
    detect: {
      enabled: dt.enabled !== false,
      challenge_score: Number(dt.challenge_score ?? 40),
      block_score: Number(dt.block_score ?? 90),
      missing_ua_score: Number(dt.missing_ua_score ?? 25),
      scanner_ua_score: Number(dt.scanner_ua_score ?? 50),
      ai_ua_score: Number(dt.ai_ua_score ?? 55),
      probe_path_score: Number(dt.probe_path_score ?? 40),
      odd_method_score: Number(dt.odd_method_score ?? 30),
      missing_accept_score: Number(dt.missing_accept_score ?? 10),
      missing_accept_lang_score: Number(dt.missing_accept_lang_score ?? 15),
      missing_sec_fetch_score: Number(dt.missing_sec_fetch_score ?? 20),
      sec_ch_ua_mismatch_score: Number(dt.sec_ch_ua_mismatch_score ?? 25),
      star_accept_browser_score: Number(dt.star_accept_browser_score ?? 15),
      high_404_threshold: Number(dt.high_404_threshold ?? 20),
      high_404_window: String(dt.high_404_window ?? '1m'),
      high_404_action: String(dt.high_404_action ?? 'challenge'),
      behavior_window: String(dt.behavior_window ?? '1m'),
      behavior_burst_limit: Number(dt.behavior_burst_limit ?? 60),
      behavior_burst_score: Number(dt.behavior_burst_score ?? 35),
      behavior_path_fanout: Number(dt.behavior_path_fanout ?? 40),
      behavior_path_fanout_score: Number(dt.behavior_path_fanout_score ?? 30),
      behavior_strike_limit: Number(dt.behavior_strike_limit ?? 3),
      behavior_strike_score: Number(dt.behavior_strike_score ?? 25),
      proxy_signals: {
        bot_score_header: String(ps.bot_score_header ?? 'CF-Bot-Score'),
        bot_score_header_2: String(ps.bot_score_header_2 ?? 'X-Bot-Score'),
        ja4_header: String(ps.ja4_header ?? 'X-JA4'),
        low_score_points: Number(ps.low_score_points ?? 40),
      },
    },
    coraza: {
      enabled: !!cz.enabled,
      loaded: !!cz.loaded,
      mode: String(cz.mode ?? 'block'),
      paranoia: Number(cz.paranoia ?? 1),
    },
    challenge: {
      enabled: ch.enabled !== false,
      mode: String(ch.mode ?? 'detect'),
      difficulty: Number(ch.difficulty ?? 16),
      algorithm: String(ch.algorithm ?? 'adaptive'),
      cookie_name: String(ch.cookie_name ?? 'rg_clear'),
      cookie_ttl: String(ch.cookie_ttl ?? '24h'),
      path_prefix: String(ch.path_prefix ?? '/_rg'),
      captcha_enabled: !!ch.captcha_enabled,
      captcha_provider: String(ch.captcha_provider ?? ''),
    },
    ui: {
      brand: String(ui.brand ?? 'RavenGuard'),
      status_text: String(ui.status_text ?? 'Checking your browser before accessing this site.'),
      logo_url: String(ui.logo_url ?? ''),
      favicon_url: String(ui.favicon_url ?? ''),
      theme_color: String(ui.theme_color ?? '#050505'),
      background: String(ui.background ?? ''),
      foreground: String(ui.foreground ?? ''),
      accent: String(ui.accent ?? ''),
      font_sans: String(ui.font_sans ?? ''),
      font_mono: String(ui.font_mono ?? ''),
      challenge_title: String(ui.challenge_title ?? ''),
      challenge_subtitle: String(ui.challenge_subtitle ?? ''),
      block_title: String(ui.block_title ?? ''),
      rate_limit_title: String(ui.rate_limit_title ?? ''),
      upstream_title: String(ui.upstream_title ?? ''),
      error_title: String(ui.error_title ?? ''),
      footer_text: String(ui.footer_text ?? ''),
      contact: String(ui.contact ?? ''),
      custom_css: String(ui.custom_css ?? ''),
      description: String(ui.description ?? ''),
      lang: String(ui.lang ?? 'en'),
      robots: String(ui.robots ?? 'noindex, nofollow'),
      privacy_notice_url: String(ui.privacy_notice_url ?? ''),
      og_image: String(ui.og_image ?? ''),
      ray_label: String(ui.ray_label ?? ''),
    },
    trust: {
      mode: String(tr.mode ?? 'edge'),
      trusted_proxies: Array.isArray(tr.trusted_proxies) ? tr.trusted_proxies.map(String) : [],
      real_ip_header: String(tr.real_ip_header ?? 'X-Real-IP'),
      proto_header: String(tr.proto_header ?? 'X-Forwarded-Proto'),
      proxy_protocol: !!tr.proxy_protocol,
    },
    stealth: {
      ray_header: String(st.ray_header ?? 'X-RavenGuard-Ray'),
      element_name: String(st.element_name ?? 'rg-check'),
      bootstrap_global: String(st.bootstrap_global ?? '__g__'),
      access_cookie_name: String(st.access_cookie_name ?? 'rg_access'),
      hide_brand_mark: !!st.hide_brand_mark,
      generic_copy: !!st.generic_copy,
      serve_manifest: st.serve_manifest !== false,
      serve_root_icons: st.serve_root_icons !== false,
      widget_input_name: String(st.widget_input_name ?? 'rg'),
    },
    privacy: {
      hash_client_ip: pv.hash_client_ip !== false,
      log_ip: String(pv.log_ip ?? 'hash'),
      retention: String(pv.retention ?? '30m'),
      privacy_notice_url: String(pv.privacy_notice_url ?? ''),
    },
    logging: {
      level: String(lg.level ?? 'info'),
      format: String(lg.format ?? 'text'),
    },
  }
  if (qf) {
    out.qfeeds = {
      enabled: !!qf.enabled,
      feeds: Array.isArray(qf.feeds) ? [...qf.feeds] : [],
      refresh: String(qf.refresh ?? '1h'),
      on_error: String(qf.on_error ?? 'fail_open'),
      base_url: String(qf.base_url ?? ''),
      limit: Number(qf.limit ?? 0),
    }
    if (qf.api_token) out.qfeeds.api_token = qf.api_token
  }
  return out
}

export interface Upstream {
  id: string
  name: string
  url: string
  connect_timeout?: string
  response_header_timeout?: string
  idle_conn_timeout?: string
  max_idle_conns?: number
  max_idle_conns_per_host?: number
  max_conns_per_host?: number
  flush_interval?: string
  set_headers?: string[]
  health_enabled: boolean
  health_path?: string
  health_interval?: string
  health_timeout?: string
  created_at: string
  updated_at: string
}

export interface Route {
  id: string
  name: string
  enabled: boolean
  hosts: string[]
  path_prefix: string
  upstream_id: string
  strip_prefix: boolean
  priority: number
  access_policy_id?: string | null
  openapi_schema_id?: string | null
  proxy_id?: string
  created_at: string
  updated_at: string
}

export interface ProxyNode {
  id: string
  name: string
  tags: string[]
  fingerprint: string
  universal: boolean
  public_ipv4: string
  public_ipv6: string
  listen_http: string
  listen_https: string
  listen_quic: string
  hostname: string
  agent_version: string
  last_seen_at?: string
  desired_revision: number
  online?: boolean
  created_at: string
  updated_at: string
  enrollment_token?: string
}

export interface DNSChecklistItem {
  host: string
  from_ipv4?: string
  from_ipv6?: string
  to_ipv4?: string
  to_ipv6?: string
  suggested_a?: string
  suggested_aaaa?: string
  note?: string
}

export interface ServiceMigration {
  id: string
  from_proxy_id: string
  to_proxy_id: string
  route_ids: string[]
  phase: string
  dns_checklist: DNSChecklistItem[]
  created_by?: number
  created_at: string
  updated_at: string
  detail: string
}

export interface AccessRule {
  type: 'password' | 'pin' | 'ip_allowlist' | 'header' | 'user_agent'
  secret?: string
  secret_hash?: string
  header_name?: string
  header_value?: string
  cidrs?: string[]
  user_agents?: string[]
}

export interface AccessPolicy {
  id: string
  name: string
  mode: string
  rules: AccessRule[]
  cookie_ttl: string
  created_at: string
  updated_at: string
}

export interface APISchema {
  id: string
  name: string
  mode: string
  spec_text: string
  created_at: string
  updated_at: string
}

export interface CertStatus {
  hostname: string
  source?: string
  state: string
  not_before?: string
  not_after?: string
  days_left?: number
  issuer?: string
  subject?: string
  serial?: string
  fingerprint_sha256?: string
  dns_names?: string[]
  last_error?: string
  managed: boolean
}

export interface LogEntry {
  time: string
  level: string
  message: string
  attrs?: Record<string, string>
}

export interface WAFEvent {
  ray: string
  action: string
  reason: string
  method: string
  path: string
  host: string
  ua: string
  ip_hash: string
  bind_id: string
  score: number
  details?: Record<string, string>
  created_at: string
}

export class APIError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'APIError'
    this.status = status
  }
}

/**
 * Joins the SPA base path with the fixed API prefix. Exported for
 * testing since it is the seam most likely to break under a
 * subdirectory deployment.
 */
export function apiURL(path: string): string {
  const trimmedBase = base.endsWith('/') ? base.slice(0, -1) : base
  const trimmedPath = path.startsWith('/') ? path : `/${path}`
  return `${trimmedBase}/api/v1${trimmedPath}`
}

let csrfToken = ''

export function setCSRFToken(token: string) {
  csrfToken = token
}

export function getCSRFToken(): string {
  return csrfToken
}

const mutatingMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {}
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }
  if (mutatingMethods.has(method) && csrfToken) {
    headers['X-CSRF-Token'] = csrfToken
  }
  const res = await fetch(apiURL(path), {
    method,
    headers,
    credentials: 'same-origin',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  let data: Record<string, unknown> = {}
  if (text) {
    try {
      data = JSON.parse(text) as Record<string, unknown>
    } catch {
      throw new APIError(res.status, res.ok ? 'invalid json response' : `request failed (${res.status})`)
    }
  }
  if (!res.ok) {
    const message = typeof data.error === 'string' ? data.error : `request failed (${res.status})`
    throw new APIError(res.status, message)
  }
  return data as T
}

export const api = {
  auth: {
    login(username: string, password: string) {
      return request<{ user: User; csrf_token: string; expires_at?: string }>('POST', '/auth/login', {
        username,
        password,
      })
    },
    logout() {
      return request<{ ok: string }>('POST', '/auth/logout')
    },
    me() {
      return request<Session>('GET', '/auth/me')
    },
    refresh() {
      return request<{ user: User; csrf_token: string; expires_at: string }>('POST', '/auth/refresh')
    },
    changePassword(current: string, next: string) {
      return request<{ ok: string }>('POST', '/auth/password', { current, new: next })
    },
    updateProfile(username: string) {
      return request<{ user: User }>('PATCH', '/auth/profile', { username })
    },
    sessions() {
      return request<{ sessions: AuthSession[] }>('GET', '/auth/sessions')
    },
    revokeSession(id: string) {
      return request<{ ok: string; signed_out: boolean }>('DELETE', `/auth/sessions/${id}`)
    },
    revokeAllSessions() {
      return request<{ ok: string; signed_out: boolean }>('DELETE', '/auth/sessions')
    },
  },

  status: {
    get() {
      return request<Status>('GET', '/status')
    },
    history() {
      return request<{ samples: StatusSample[] }>('GET', '/status/history')
    },
  },

  bans: {
    list() {
      return request<{ bans: Ban[] }>('GET', '/bans')
    },
    create(key: string) {
      return request<{ ok: string }>('POST', '/bans', { key })
    },
    remove(key: string) {
      return request<{ ok: boolean }>('DELETE', `/bans?key=${encodeURIComponent(key)}`)
    },
  },

  blocklists: {
    stats() {
      return request<BlocklistStats>('GET', '/blocklists')
    },
    reload() {
      return request<BlocklistStats>('POST', '/blocklists/reload')
    },
    entries(kind: string) {
      return request<{ kind: string; entries: string[] }>('GET', `/blocklists/entries?kind=${encodeURIComponent(kind)}`)
    },
    add(kind: string, value: string) {
      return request<{ kind: string; entries: string[]; stats: BlocklistStats }>('POST', '/blocklists/entries', {
        kind,
        value,
      })
    },
    edit(kind: string, from: string, to: string) {
      return request<{ kind: string; entries: string[]; stats: BlocklistStats }>('PUT', '/blocklists/entries', {
        kind,
        from,
        to,
      })
    },
    remove(kind: string, value: string) {
      return request<{ kind: string; entries: string[]; stats: BlocklistStats }>(
        'DELETE',
        `/blocklists/entries?kind=${encodeURIComponent(kind)}&value=${encodeURIComponent(value)}`,
      )
    },
  },

  qfeeds: {
    get() {
      return request<{ status: QFeedsStatus; config: QFeedsSafe }>('GET', '/qfeeds')
    },
    update(safe: QFeedsSafe) {
      return request<{ status: QFeedsStatus; config: QFeedsSafe }>('PUT', '/qfeeds', safe)
    },
    refresh() {
      return request<{ status: QFeedsStatus }>('POST', '/qfeeds/refresh')
    },
  },

  config: {
    get() {
      return request<ConfigView>('GET', '/config')
    },
    update(safe: SafeConfig) {
      return request<ConfigView>('PUT', '/config', safe)
    },
    async export() {
      const view = await request<ConfigView>('GET', '/config')
      const blob = new Blob([JSON.stringify(view, null, 2)], { type: 'application/json' })
      const href = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = href
      a.download = 'ravenguard-config.json'
      a.rel = 'noopener'
      a.click()
      URL.revokeObjectURL(href)
      return view
    },
    async setModuleEnabled(key: ModuleKey, enabled: boolean) {
      if (key === 'qfeeds') {
        const res = await request<{ status: QFeedsStatus; config: QFeedsSafe }>('GET', '/qfeeds')
        const cfg = { ...res.config }
        cfg.enabled = enabled
        if (!cfg.api_token) delete cfg.api_token
        return request<{ status: QFeedsStatus; config: QFeedsSafe }>('PUT', '/qfeeds', cfg)
      }
      const view = await request<ConfigView>('GET', '/config')
      const live = normalizeSafeConfig(view.live)
      if (key === 'protect') live.protect.enabled = enabled
      else if (key === 'ratelimit') live.ratelimit.enabled = enabled
      else if (key === 'detect') live.detect.enabled = enabled
      else live.challenge.enabled = enabled
      return request<ConfigView>('PUT', '/config', live)
    },
  },

  appearance: {
    previewURL(page: string) {
      return apiURL(`/appearance/preview?page=${encodeURIComponent(page)}`)
    },
    async preview(page: string, draft: SafeConfig | Pick<SafeConfig, 'ui' | 'stealth'>): Promise<string> {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' }
      if (csrfToken) headers['X-CSRF-Token'] = csrfToken
      const res = await fetch(apiURL(`/appearance/preview?page=${encodeURIComponent(page)}`), {
        method: 'POST',
        headers,
        credentials: 'same-origin',
        body: JSON.stringify(draft),
      })
      const text = await res.text()
      if (!res.ok) {
        let message = `request failed (${res.status})`
        try {
          const data = JSON.parse(text) as { error?: string }
          if (typeof data.error === 'string') message = data.error
        } catch {
          if (text) message = text
        }
        throw new APIError(res.status, message)
      }
      return text
    },
    async upload(kind: 'logo' | 'favicon', file: File) {
      const fd = new FormData()
      fd.append('file', file)
      fd.append('kind', kind)
      const headers: Record<string, string> = {}
      if (csrfToken) headers['X-CSRF-Token'] = csrfToken
      const res = await fetch(apiURL(`/appearance/assets?kind=${encodeURIComponent(kind)}`), {
        method: 'POST',
        headers,
        credentials: 'same-origin',
        body: fd,
      })
      const text = await res.text()
      let data: Record<string, unknown> = {}
      if (text) {
        try {
          data = JSON.parse(text) as Record<string, unknown>
        } catch {
          throw new APIError(res.status, res.ok ? 'invalid json response' : `request failed (${res.status})`)
        }
      }
      if (!res.ok) {
        const message = typeof data.error === 'string' ? data.error : `request failed (${res.status})`
        throw new APIError(res.status, message)
      }
      return data as { url: string }
    },
  },

  logs: {
    list(limit = 200, level = '') {
      const params = new URLSearchParams()
      if (limit) params.set('limit', String(limit))
      if (level) params.set('level', level)
      const qs = params.toString()
      return request<{ logs: LogEntry[] }>('GET', `/logs${qs ? `?${qs}` : ''}`)
    },
  },

  requests: {
    list(limit = 50, proxyId = '') {
      const params = new URLSearchParams()
      if (limit) params.set('limit', String(limit))
      if (proxyId) params.set('proxy_id', proxyId)
      const qs = params.toString()
      return request<{ events: WAFEvent[] }>('GET', `/requests${qs ? `?${qs}` : ''}`)
    },
    get(ray: string, proxyId = '') {
      const params = new URLSearchParams()
      if (proxyId) params.set('proxy_id', proxyId)
      const qs = params.toString()
      return request<{ event: WAFEvent }>(
        'GET',
        `/requests/${encodeURIComponent(ray)}${qs ? `?${qs}` : ''}`,
      )
    },
  },

  audit: {
    list(cursor?: number, limit?: number) {
      const params = new URLSearchParams()
      if (cursor) params.set('cursor', String(cursor))
      if (limit) params.set('limit', String(limit))
      const qs = params.toString()
      return request<{ events: AuditEvent[] }>('GET', `/audit${qs ? `?${qs}` : ''}`)
    },
  },

  users: {
    list() {
      return request<{ users: User[] }>('GET', '/users')
    },
    create(username: string, password: string, role: Role) {
      return request<User>('POST', '/users', { username, password, role })
    },
    update(id: number, patch: { role?: Role; disabled?: boolean }) {
      return request<User>('PATCH', `/users/${id}`, patch)
    },
    remove(id: number) {
      return request<{ ok: string }>('DELETE', `/users/${id}`)
    },
  },

  tokens: {
    list() {
      return request<{ tokens: APIToken[] }>('GET', '/tokens')
    },
    create(name: string, role?: Role, expiresIn?: string) {
      return request<{ token: APIToken; secret: string }>('POST', '/tokens', {
        name,
        role,
        expires_in: expiresIn,
      })
    },
    revoke(id: string) {
      return request<{ ok: string }>('DELETE', `/tokens/${id}`)
    },
  },

  upstreams: {
    list() {
      return request<{ upstreams: Upstream[] }>('GET', '/upstreams')
    },
    create(body: Partial<Upstream>) {
      return request<Upstream>('POST', '/upstreams', body)
    },
    get(id: string) {
      return request<Upstream>('GET', `/upstreams/${encodeURIComponent(id)}`)
    },
    update(id: string, body: Partial<Upstream>) {
      return request<Upstream>('PUT', `/upstreams/${encodeURIComponent(id)}`, body)
    },
    remove(id: string) {
      return request<{ ok: string }>('DELETE', `/upstreams/${encodeURIComponent(id)}`)
    },
  },

  routes: {
    list() {
      return request<{ routes: Route[] }>('GET', '/routes')
    },
    create(body: Partial<Route>) {
      return request<Route>('POST', '/routes', body)
    },
    get(id: string) {
      return request<Route>('GET', `/routes/${encodeURIComponent(id)}`)
    },
    update(id: string, body: Partial<Route>) {
      return request<Route>('PUT', `/routes/${encodeURIComponent(id)}`, body)
    },
    remove(id: string) {
      return request<{ ok: string }>('DELETE', `/routes/${encodeURIComponent(id)}`)
    },
  },

  accessPolicies: {
    list() {
      return request<{ access_policies: AccessPolicy[] }>('GET', '/access-policies')
    },
    create(body: Partial<AccessPolicy>) {
      return request<AccessPolicy>('POST', '/access-policies', body)
    },
    get(id: string) {
      return request<AccessPolicy>('GET', `/access-policies/${encodeURIComponent(id)}`)
    },
    update(id: string, body: Partial<AccessPolicy>) {
      return request<AccessPolicy>('PUT', `/access-policies/${encodeURIComponent(id)}`, body)
    },
    remove(id: string) {
      return request<{ ok: string }>('DELETE', `/access-policies/${encodeURIComponent(id)}`)
    },
  },

  apiSchemas: {
    list() {
      return request<{ api_schemas: APISchema[] }>('GET', '/api-schemas')
    },
    create(body: Partial<APISchema>) {
      return request<APISchema>('POST', '/api-schemas', body)
    },
    get(id: string) {
      return request<APISchema>('GET', `/api-schemas/${encodeURIComponent(id)}`)
    },
    update(id: string, body: Partial<APISchema>) {
      return request<APISchema>('PUT', `/api-schemas/${encodeURIComponent(id)}`, body)
    },
    remove(id: string) {
      return request<{ ok: string }>('DELETE', `/api-schemas/${encodeURIComponent(id)}`)
    },
  },

  certs: {
    list() {
      return request<{ certs: CertStatus[] }>('GET', '/certs')
    },
    get(host: string) {
      return request<CertStatus>('GET', `/certs/${encodeURIComponent(host)}`)
    },
    renew(host: string) {
      return request<{ ok: string }>('POST', `/certs/${encodeURIComponent(host)}/renew`)
    },
    upload(host: string, cert_pem: string, key_pem: string) {
      return request<{ ok: string }>('PUT', `/certs/${encodeURIComponent(host)}`, { cert_pem, key_pem })
    },
    generate(host: string, body?: { validity?: string; dns_names?: string[] }) {
      return request<CertStatus>('POST', `/certs/${encodeURIComponent(host)}/generate`, body ?? {})
    },
    remove(host: string) {
      return request<{ ok: string }>('DELETE', `/certs/${encodeURIComponent(host)}`)
    },
    manage(hosts: string[]) {
      return request<{ ok: string }>('POST', '/certs/manage', { hosts })
    },
  },

  proxies: {
    list() {
      return request<{
        proxies: ProxyNode[]
        hub_url: string
        hub_pubkey: string
        connect_path: string
      }>('GET', '/proxies')
    },
    create(body: {
      name: string
      tags?: string[]
      public_ipv4?: string
      public_ipv6?: string
      universal?: boolean
    }) {
      return request<{
        proxy: ProxyNode
        enrollment_token: string
        hub_url: string
        hub_pubkey: string
        install: { hub_url: string; token: string; hub_pubkey: string }
      }>('POST', '/proxies', body)
    },
    update(id: string, body: Partial<ProxyNode>) {
      return request<{ proxy: ProxyNode }>('PUT', `/proxies/${encodeURIComponent(id)}`, body)
    },
    remove(id: string) {
      return request<{ status: string }>('DELETE', `/proxies/${encodeURIComponent(id)}`)
    },
    rotateToken(id: string) {
      return request<{
        proxy: ProxyNode
        enrollment_token: string
        hub_url: string
        hub_pubkey: string
      }>('POST', `/proxies/${encodeURIComponent(id)}/rotate-token`)
    },
    push(id: string) {
      return request<{ status: string }>('POST', `/proxies/${encodeURIComponent(id)}/push`)
    },
    status(id: string) {
      return request<Status>('GET', `/proxies/${encodeURIComponent(id)}/status`)
    },
  },

  migrations: {
    list() {
      return request<{ migrations: ServiceMigration[] }>('GET', '/migrations')
    },
    create(body: { from_proxy_id: string; to_proxy_id: string; route_ids: string[] }) {
      return request<{ migration: ServiceMigration }>('POST', '/migrations', body)
    },
    get(id: string) {
      return request<{ migration: ServiceMigration }>('GET', `/migrations/${encodeURIComponent(id)}`)
    },
    prep(id: string) {
      return request<{ migration: ServiceMigration }>('POST', `/migrations/${encodeURIComponent(id)}/prep`)
    },
    complete(id: string) {
      return request<{ migration: ServiceMigration }>(
        'POST',
        `/migrations/${encodeURIComponent(id)}/complete`,
      )
    },
    abort(id: string) {
      return request<{ migration: ServiceMigration }>('POST', `/migrations/${encodeURIComponent(id)}/abort`)
    },
  },
}
