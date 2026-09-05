import {
  encodePayload,
  type Challenge,
  type EnvAttestation,
  type Payload,
  type WidgetState,
} from './protocol'
import { styles } from './styles'

export type AutoMode = 'off' | 'onload' | 'onsubmit' | 'onfocus'

export interface WidgetOptions {
  challenge?: string | Challenge
  name?: string
  auto?: AutoMode
  workers?: number
  language?: string
  theme?: string
  display?: 'standard' | 'invisible'
  debug?: boolean
  test?: boolean
}

const labels: Record<WidgetState, string> = {
  unverified: 'Verify you are human',
  verifying: 'Working…',
  verified: 'Verified',
  error: 'Verification failed',
  expired: 'Challenge expired',
}

function hasCdcKeys(obj: object | null | undefined): boolean {
  if (!obj) return false
  try {
    for (const key of Object.getOwnPropertyNames(obj)) {
      if (key.startsWith('cdc_') || key.startsWith('$cdc_')) return true
    }
  } catch {
    return false
  }
  return false
}

function collectEnv(interacted: boolean, solveMs: number): EnvAttestation {
  const nav = typeof navigator !== 'undefined' ? navigator : undefined
  const win = typeof window !== 'undefined' ? (window as unknown as Record<string, unknown>) : {}
  const doc = typeof document !== 'undefined' ? (document as unknown as Record<string, unknown>) : {}
  const ua = nav?.userAgent ?? ''
  const playwright = Boolean(
    win.__playwright ||
      win.__pw_manual ||
      win.playwright ||
      win.__puppeteer_evaluation_script__ ||
      doc.__puppeteer_evaluation_script__,
  )
  const selenium = Boolean(
    win._selenium ||
      win.__selenium_unwrapped ||
      win._Selenium_IDE_Recorder ||
      win.callSelenium ||
      win.__webdriver_script_fn ||
      win.__driver_evaluate ||
      win.__webdriver_evaluate ||
      win.__selenium_evaluate ||
      doc.__selenium_unwrapped ||
      doc.__webdriver_evaluate ||
      doc.__driver_evaluate ||
      doc.$cdc_asdjflasutopfhvcZLmcfl_ ||
      hasCdcKeys(win) ||
      hasCdcKeys(doc),
  )
  const chromeMissing =
    /Chrome\//i.test(ua) &&
    !/Edg\//i.test(ua) &&
    !/OPR\//i.test(ua) &&
    !/Firefox\//i.test(ua) &&
    typeof win.chrome === 'undefined'
  const headless =
    /HeadlessChrome|Headless|PhantomJS/i.test(ua) || (chromeMissing && (!nav?.plugins || nav.plugins.length === 0))
  return {
    webdriver: Boolean(nav && 'webdriver' in nav && (nav as Navigator & { webdriver?: boolean }).webdriver),
    playwright,
    selenium,
    headless,
    no_plugins: !nav?.plugins || nav.plugins.length === 0,
    interacted,
    solve_ms: solveMs,
  }
}

const capturedScriptSrc =
  typeof document !== 'undefined' && document.currentScript instanceof HTMLScriptElement
    ? document.currentScript.src
    : ''

function workerBaseURL(): string {
  let meta = ''
  try {
    meta = import.meta.url
  } catch {
    meta = ''
  }
  return meta || capturedScriptSrc || (typeof location !== 'undefined' ? location.href : '')
}

function workerURL(algo: string): URL {
  const file = algo === 'PBKDF2-SHA256' ? './workers/pbkdf2.js' : './workers/sha256.js'
  return new URL(file, workerBaseURL())
}

async function solveInWorkers(ch: Challenge, workerCount: number): Promise<number> {
  const { solveChallenge } = await import('./protocol')
  if (typeof Worker === 'undefined' || !workerBaseURL()) {
    return solveChallenge(ch)
  }
  try {
    const limit = ch.maxnumber > 0 ? ch.maxnumber : 1 << Math.min(ch.difficulty + 3, 32)
    const n = Math.max(1, Math.min(workerCount, 8))
    const chunk = Math.ceil((limit + 1) / n)
    const url = workerURL(ch.algorithm)
    return await new Promise<number>((resolve, reject) => {
      let remaining = n
      let settled = false
      const workers: Worker[] = []
      const cleanup = () => {
        for (const w of workers) w.terminate()
      }
      for (let i = 0; i < n; i++) {
        const start = i * chunk
        const end = Math.min(limit, start + chunk - 1)
        if (start > limit) {
          remaining--
          continue
        }
        let w: Worker
        try {
          w = new Worker(url, { type: 'module' })
        } catch (e) {
          cleanup()
          reject(e)
          return
        }
        workers.push(w)
        w.onmessage = (ev: MessageEvent<{ found?: number; done: boolean; error?: string }>) => {
          if (settled) return
          if (ev.data.error) {
            settled = true
            cleanup()
            reject(new Error(ev.data.error))
            return
          }
          if (ev.data.found !== undefined) {
            settled = true
            cleanup()
            resolve(ev.data.found)
            return
          }
          remaining--
          if (remaining <= 0) {
            settled = true
            cleanup()
            reject(new Error('no solution within maxnumber'))
          }
        }
        w.onerror = () => {
          if (settled) return
          settled = true
          cleanup()
          reject(new Error('worker failed'))
        }
        w.postMessage({ id: i, challenge: ch, start, end })
      }
    })
  } catch {
    return solveChallenge(ch)
  }
}

export class RavenGuardWidget extends HTMLElement {
  static formAssociated = true

  #opts: WidgetOptions = {
    name: 'rg',
    auto: 'onload',
    workers: 2,
    display: 'standard',
  }
  #state: WidgetState = 'unverified'
  #payload = ''
  #interacted = false
  #internals: ElementInternals | null = null
  #hidden: HTMLInputElement | null = null
  #root: ShadowRoot
  #labelEl: HTMLElement | null = null
  #checkEl: HTMLButtonElement | null = null
  #started = false

  constructor() {
    super()
    this.#root = this.attachShadow({ mode: 'open' })
    try {
      this.#internals = this.attachInternals()
    } catch {
      this.#internals = null
    }
  }

  static get observedAttributes() {
    return ['challenge', 'name', 'auto', 'workers', 'display', 'debug', 'test', 'theme']
  }

  connectedCallback() {
    this.#readAttrs()
    this.#render()
    this.#applyTheme()
    this.#armInteraction()
    queueMicrotask(() => {
      this.dispatchEvent(new CustomEvent('load', { bubbles: true }))
      if (this.#opts.auto === 'onload') void this.verify()
    })
  }

  attributeChangedCallback() {
    this.#readAttrs()
    this.#applyTheme()
    this.#ensureHidden()
  }

  configure(opts: WidgetOptions) {
    this.#opts = { ...this.#opts, ...opts }
    if (opts.theme !== undefined) {
      if (opts.theme) this.setAttribute('theme', opts.theme)
      else this.removeAttribute('theme')
    }
    this.#applyTheme()
    this.#ensureHidden()
    if (opts.challenge !== undefined) {
      this.#started = false
      this.#setState('unverified')
    }
  }

  getConfiguration(): WidgetOptions {
    return { ...this.#opts }
  }

  getState(): WidgetState {
    return this.#state
  }

  get payload(): string {
    return this.#payload
  }

  reset(state: WidgetState = 'unverified') {
    this.#payload = ''
    this.#started = false
    this.#syncValue('')
    this.#setState(state)
  }

  async verify(): Promise<string> {
    if (this.#state === 'verifying' || this.#started) return this.#payload
    this.#started = true
    this.#setState('verifying')
    const t0 = performance.now()
    try {
      if (this.#opts.test) {
        this.#payload = 'test'
        this.#syncValue(this.#payload)
        this.#setState('verified')
        this.dispatchEvent(new CustomEvent('verified', { detail: { payload: this.#payload }, bubbles: true }))
        return this.#payload
      }
      const ch = await this.#loadChallenge()
      if (Date.now() / 1000 > ch.expires) {
        this.#setState('expired')
        this.dispatchEvent(new CustomEvent('expired', { bubbles: true }))
        throw new Error('expired')
      }
      const workers = this.#opts.workers ?? 2
      const sol = await solveInWorkers(ch, workers)
      const solveMs = Math.round(performance.now() - t0)
      const env = collectEnv(this.#interacted, solveMs)
      const payload: Payload = {
        v: ch.v,
        algorithm: ch.algorithm,
        challenge: ch.challenge,
        salt: ch.salt,
        difficulty: ch.difficulty,
        maxnumber: ch.maxnumber,
        expires: ch.expires,
        bind: ch.bind,
        gate: ch.gate,
        params: ch.params,
        signature: ch.signature,
        solution: String(sol),
        env,
      }
      this.#payload = encodePayload(payload)
      this.#syncValue(this.#payload)
      this.#setState('verified')
      this.dispatchEvent(new CustomEvent('verified', { detail: { payload: this.#payload }, bubbles: true }))
      return this.#payload
    } catch (e) {
      this.#started = false
      this.#setState('error')
      this.dispatchEvent(
        new CustomEvent('error', {
          detail: { error: e instanceof Error ? e.message : String(e) },
          bubbles: true,
        }),
      )
      throw e
    }
  }

  #readAttrs() {
    const challenge = this.getAttribute('challenge')
    if (challenge) this.#opts.challenge = challenge
    const name = this.getAttribute('name')
    if (name) this.#opts.name = name
    const auto = this.getAttribute('auto') as AutoMode | null
    if (auto) this.#opts.auto = auto
    const workers = this.getAttribute('workers')
    if (workers) this.#opts.workers = Number(workers) || 2
    const display = this.getAttribute('display') as 'standard' | 'invisible' | null
    if (display) this.#opts.display = display
    this.#opts.debug = this.hasAttribute('debug')
    this.#opts.test = this.hasAttribute('test')
    const theme = this.getAttribute('theme')
    if (theme) this.#opts.theme = theme
  }

  #prefersLight(): boolean {
    return Boolean(globalThis.matchMedia?.('(prefers-color-scheme: light)').matches)
  }

  #applyTheme() {
    let theme = (this.getAttribute('theme') || this.#opts.theme || '').trim().toLowerCase()
    if (theme === 'auto') {
      theme = this.#prefersLight() ? 'light' : 'dark'
      if (this.getAttribute('theme') !== theme) this.setAttribute('theme', theme)
    }
    if (theme) this.#opts.theme = theme
  }

  #render() {
    this.#root.innerHTML = ''
    const style = document.createElement('style')
    style.textContent = styles
    const wrap = document.createElement('div')
    wrap.className = 'rg-root'
    const btn = document.createElement('button')
    btn.type = 'button'
    btn.className = 'rg-check'
    btn.setAttribute('aria-label', 'Verify')
    btn.addEventListener('click', () => {
      this.#interacted = true
      void this.verify()
    })
    const label = document.createElement('div')
    label.className = 'rg-label'
    label.textContent = labels[this.#state]
    wrap.append(btn, label)
    this.#root.append(style, wrap)
    this.#checkEl = btn
    this.#labelEl = label
    this.#ensureHidden()
    this.#paint()
  }

  #ensureHidden() {
    const name = this.#opts.name ?? 'rg'
    if (!this.#hidden) {
      this.#hidden = document.createElement('input')
      this.#hidden.type = 'hidden'
      this.#hidden.name = name
      this.append(this.#hidden)
    } else {
      this.#hidden.name = name
    }
  }

  #syncValue(v: string) {
    if (this.#hidden) this.#hidden.value = v
    if (this.#internals && 'setFormValue' in this.#internals) {
      this.#internals.setFormValue(v)
    }
  }

  #setState(s: WidgetState) {
    this.#state = s
    this.#paint()
    this.dispatchEvent(new CustomEvent('statechange', { detail: { state: s }, bubbles: true }))
  }

  #paint() {
    if (this.#checkEl) {
      this.#checkEl.dataset.state = this.#state
      this.#checkEl.disabled = this.#state === 'verifying' || this.#state === 'verified'
      this.#checkEl.setAttribute('aria-busy', this.#state === 'verifying' ? 'true' : 'false')
      if (this.#state === 'verifying') {
        const spin = document.createElement('span')
        spin.className = 'rg-spinner'
        spin.setAttribute('aria-hidden', 'true')
        this.#checkEl.replaceChildren(spin)
      } else if (this.#state === 'verified') {
        this.#checkEl.replaceChildren(document.createTextNode('OK'))
      } else {
        this.#checkEl.replaceChildren()
      }
    }
    if (this.#labelEl) {
      this.#labelEl.textContent = labels[this.#state]
    }
  }

  #armInteraction() {
    const mark = () => {
      this.#interacted = true
    }
    for (const ev of ['pointerdown', 'keydown', 'touchstart'] as const) {
      this.addEventListener(ev, mark, { once: true, passive: true })
    }
    const form = this.closest('form')
    if (form && this.#opts.auto === 'onsubmit') {
      form.addEventListener(
        'submit',
        (e) => {
          if (this.#state === 'verified') return
          e.preventDefault()
          void this.verify().then(() => form.requestSubmit())
        },
        { capture: true },
      )
    }
  }

  async #loadChallenge(): Promise<Challenge> {
    const src = this.#opts.challenge
    if (!src) throw new Error('challenge URL or object required')
    if (typeof src !== 'string') return src
    const trimmed = src.trim()
    if (trimmed.startsWith('{')) return JSON.parse(trimmed) as Challenge
    const res = await fetch(trimmed, { credentials: 'same-origin' })
    if (!res.ok) throw new Error(`challenge fetch failed: ${res.status}`)
    return (await res.json()) as Challenge
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'rg-check': RavenGuardWidget
    'ravenguard-widget': RavenGuardWidget
  }
}
