import { describe, expect, it } from 'vitest'
import { api, apiURL, normalizeSafeConfig } from './api'

describe('apiURL', () => {
  it('joins the empty base path with the api prefix', () => {
    expect(apiURL('/status')).toBe('/api/v1/status')
  })

  it('normalizes paths missing a leading slash', () => {
    expect(apiURL('status')).toBe('/api/v1/status')
  })

  it('preserves query strings', () => {
    expect(apiURL('/bans?key=1.2.3.4')).toBe('/api/v1/bans?key=1.2.3.4')
  })
})

describe('appearance helpers', () => {
  it('builds a preview URL', () => {
    expect(api.appearance.previewURL('challenge')).toBe('/api/v1/appearance/preview?page=challenge')
  })
})

describe('normalizeSafeConfig', () => {
  it('fills expanded live fields from defaults', () => {
    const cfg = normalizeSafeConfig({})
    expect(cfg.ui.brand).toBe('RavenGuard')
    expect(cfg.ui.theme_color).toBe('#050505')
    expect(cfg.detect.missing_ua_score).toBe(25)
    expect(cfg.detect.proxy_signals.ja4_header).toBe('X-JA4')
    expect(cfg.challenge.algorithm).toBe('adaptive')
    expect(cfg.challenge.path_prefix).toBe('/_rg')
    expect(cfg.trust.mode).toBe('edge')
    expect(cfg.stealth.ray_header).toBe('X-RavenGuard-Ray')
    expect(cfg.privacy.log_ip).toBe('hash')
    expect(cfg.logging.format).toBe('text')
    expect(cfg.qfeeds).toBeUndefined()
  })

  it('keeps posted qfeeds and proxy lists', () => {
    const cfg = normalizeSafeConfig({
      trust: {
        mode: 'behind_proxy',
        trusted_proxies: ['10.0.0.1/32'],
        real_ip_header: '',
        proto_header: '',
        proxy_protocol: true,
      },
      qfeeds: {
        enabled: true,
        feeds: ['malware_ip'],
        refresh: '2h',
        on_error: 'fail_closed',
        base_url: 'https://x',
        limit: 3,
      },
    })
    expect(cfg.trust.mode).toBe('behind_proxy')
    expect(cfg.trust.trusted_proxies).toEqual(['10.0.0.1/32'])
    expect(cfg.trust.proxy_protocol).toBe(true)
    expect(cfg.qfeeds?.enabled).toBe(true)
    expect(cfg.qfeeds?.feeds).toEqual(['malware_ip'])
  })
})
