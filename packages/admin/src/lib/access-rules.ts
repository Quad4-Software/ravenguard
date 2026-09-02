import type { AccessRule } from '$lib/api'

export type RuleType = AccessRule['type']

/** Form state for one access rule before it is sent to the API. */
export interface DraftRule {
  id: number
  type: RuleType
  secret: string
  secret_hash?: string
  cidrs: string
  header_name: string
  header_value: string
  user_agents: string
}

let nextDraftId = 0

function allocId(): number {
  nextDraftId += 1
  return nextDraftId
}

/** Splits comma or newline separated values. */
export function splitList(value: string): string[] {
  return value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

export function emptyDraft(type: RuleType = 'password'): DraftRule {
  return {
    id: allocId(),
    type,
    secret: '',
    cidrs: '',
    header_name: '',
    header_value: '',
    user_agents: '',
  }
}

export function draftFromRule(rule: AccessRule): DraftRule {
  return {
    id: allocId(),
    type: rule.type,
    secret: '',
    secret_hash: rule.secret_hash,
    cidrs: (rule.cidrs ?? []).join('\n'),
    header_name: rule.header_name ?? '',
    header_value: rule.header_value ?? '',
    user_agents: (rule.user_agents ?? []).join('\n'),
  }
}

/**
 * Converts a draft rule to an API payload.
 * When keepHash is true, an empty password or pin secret resends secret_hash
 * so UpdateAccessPolicy does not wipe the stored hash.
 */
export function draftToRule(draft: DraftRule, keepHash: boolean): AccessRule | null {
  switch (draft.type) {
    case 'password':
    case 'pin': {
      const secret = draft.secret.trim()
      if (secret) {
        return { type: draft.type, secret }
      }
      if (keepHash && draft.secret_hash) {
        return { type: draft.type, secret_hash: draft.secret_hash }
      }
      return null
    }
    case 'ip_allowlist': {
      const cidrs = splitList(draft.cidrs)
      if (cidrs.length === 0) return null
      return { type: 'ip_allowlist', cidrs }
    }
    case 'header': {
      const header_name = draft.header_name.trim()
      const header_value = draft.header_value.trim()
      if (!header_name || !header_value) return null
      return { type: 'header', header_name, header_value }
    }
    case 'user_agent': {
      const user_agents = splitList(draft.user_agents)
      if (user_agents.length === 0) return null
      return { type: 'user_agent', user_agents }
    }
    default:
      return null
  }
}

/** Returns null if any draft is incomplete. */
export function draftsToRules(drafts: DraftRule[], keepHash: boolean): AccessRule[] | null {
  const out: AccessRule[] = []
  for (const draft of drafts) {
    const rule = draftToRule(draft, keepHash)
    if (!rule) return null
    out.push(rule)
  }
  return out
}
