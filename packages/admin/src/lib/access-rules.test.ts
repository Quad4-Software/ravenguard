import { describe, expect, it } from 'vitest'
import { draftFromRule, draftToRule, draftsToRules, emptyDraft, splitList } from './access-rules'

describe('splitList', () => {
  it('splits commas and newlines', () => {
    expect(splitList('10.0.0.0/8, 192.168.0.0/16')).toEqual(['10.0.0.0/8', '192.168.0.0/16'])
    expect(splitList('bot\ncrawler\n')).toEqual(['bot', 'crawler'])
  })
})

describe('draftToRule', () => {
  it('sends a new password secret', () => {
    const draft = emptyDraft('password')
    draft.secret = 'hunter2-long'
    expect(draftToRule(draft, false)).toEqual({ type: 'password', secret: 'hunter2-long' })
  })

  it('rejects an empty password on create', () => {
    expect(draftToRule(emptyDraft('password'), false)).toBeNull()
  })

  it('keeps secret_hash when the secret is left blank on update', () => {
    const draft = draftFromRule({ type: 'pin', secret_hash: '$argon2id$v=19$kept' })
    expect(draftToRule(draft, true)).toEqual({ type: 'pin', secret_hash: '$argon2id$v=19$kept' })
  })

  it('does not keep a hash on create', () => {
    const draft = draftFromRule({ type: 'password', secret_hash: '$argon2id$v=19$kept' })
    expect(draftToRule(draft, false)).toBeNull()
  })

  it('prefers a new secret over the stored hash', () => {
    const draft = draftFromRule({ type: 'password', secret_hash: '$argon2id$v=19$kept' })
    draft.secret = 'replacement-secret'
    expect(draftToRule(draft, true)).toEqual({ type: 'password', secret: 'replacement-secret' })
  })

  it('builds allowlist and header rules', () => {
    const cidr = emptyDraft('ip_allowlist')
    cidr.cidrs = '10.0.0.0/8\n192.168.1.0/24'
    expect(draftToRule(cidr, false)).toEqual({
      type: 'ip_allowlist',
      cidrs: ['10.0.0.0/8', '192.168.1.0/24'],
    })

    const header = emptyDraft('header')
    header.header_name = 'X-Token'
    header.header_value = 'abc'
    expect(draftToRule(header, false)).toEqual({
      type: 'header',
      header_name: 'X-Token',
      header_value: 'abc',
    })
  })
})

describe('draftsToRules', () => {
  it('returns null when any rule is incomplete', () => {
    const ok = emptyDraft('password')
    ok.secret = 'long-enough-secret'
    expect(draftsToRules([ok, emptyDraft('pin')], false)).toBeNull()
  })

  it('returns every complete rule', () => {
    const a = emptyDraft('password')
    a.secret = 'long-enough-secret'
    const b = emptyDraft('user_agent')
    b.user_agents = 'curl'
    expect(draftsToRules([a, b], false)).toEqual([
      { type: 'password', secret: 'long-enough-secret' },
      { type: 'user_agent', user_agents: ['curl'] },
    ])
  })
})
