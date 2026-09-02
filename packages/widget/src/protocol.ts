export const PROTOCOL_VERSION = 1

export type Algorithm = 'SHA-256' | 'PBKDF2-SHA256' | 'ARGON2ID'

export interface ChallengeParams {
  iterations?: number
  memory?: number
  parallelism?: number
}

export interface Challenge {
  v: number
  algorithm: Algorithm | string
  challenge: string
  salt?: string
  difficulty: number
  maxnumber: number
  expires: number
  bind?: string
  params?: Record<string, number>
  signature: string
}

export interface EnvAttestation {
  webdriver: boolean
  playwright: boolean
  selenium: boolean
  headless: boolean
  no_plugins: boolean
  interacted: boolean
  solve_ms: number
}

export interface Payload {
  v: number
  algorithm: string
  challenge: string
  salt?: string
  difficulty: number
  maxnumber: number
  expires: number
  bind?: string
  params?: Record<string, number>
  signature: string
  solution: string
  env: EnvAttestation
}

export type WidgetState =
  | 'unverified'
  | 'verifying'
  | 'verified'
  | 'error'
  | 'expired'

export function encodePayload(payload: Payload): string {
  const json = JSON.stringify(payload)
  const bytes = new TextEncoder().encode(json)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function decodePayload(raw: string): Payload {
  const padded = raw.replace(/-/g, '+').replace(/_/g, '/')
  const pad = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4))
  const bin = atob(padded + pad)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return JSON.parse(new TextDecoder().decode(bytes)) as Payload
}

export function leadingZeroBits(buf: ArrayBuffer | Uint8Array): number {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  let n = 0
  for (const c of b) {
    if (c === 0) {
      n += 8
      continue
    }
    for (let i = 7; i >= 0; i--) {
      if ((c & (1 << i)) === 0) n++
      else return n
    }
  }
  return n
}

export async function hashSHA256Solution(
  challenge: string,
  solution: number,
): Promise<ArrayBuffer> {
  const enc = new TextEncoder()
  const nonce = enc.encode(challenge)
  const colon = enc.encode(':')
  const num = new ArrayBuffer(8)
  new DataView(num).setBigUint64(0, BigInt(solution), false)
  const body = new Uint8Array(nonce.length + colon.length + 8)
  body.set(nonce, 0)
  body.set(colon, nonce.length)
  body.set(new Uint8Array(num), nonce.length + colon.length)
  return crypto.subtle.digest('SHA-256', body)
}

export async function verifySHA256(
  challenge: string,
  solution: number,
  difficulty: number,
): Promise<boolean> {
  const digest = await hashSHA256Solution(challenge, solution)
  return leadingZeroBits(digest) >= difficulty
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export async function verifyPBKDF2(
  challenge: string,
  saltHex: string,
  solution: number,
  difficulty: number,
  iterations: number,
): Promise<boolean> {
  const password = new TextEncoder().encode(`${challenge}:${solution}`)
  const saltBytes = hexToBytes(saltHex)
  const salt = saltBytes.buffer.slice(
    saltBytes.byteOffset,
    saltBytes.byteOffset + saltBytes.byteLength,
  ) as ArrayBuffer
  const key = await crypto.subtle.importKey('raw', password, 'PBKDF2', false, [
    'deriveBits',
  ])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    key,
    256,
  )
  return leadingZeroBits(bits) >= difficulty
}

export async function solveChallenge(ch: Challenge): Promise<number> {
  const limit = ch.maxnumber > 0 ? ch.maxnumber : 1 << Math.min(ch.difficulty + 3, 32)
  const algo = ch.algorithm
  const iters = ch.params?.iterations ?? 10000
  for (let i = 0; i <= limit; i++) {
    let ok = false
    if (algo === 'PBKDF2-SHA256') {
      if (!ch.salt) throw new Error('missing salt')
      ok = await verifyPBKDF2(ch.challenge, ch.salt, i, ch.difficulty, iters)
    } else {
      ok = await verifySHA256(ch.challenge, i, ch.difficulty)
    }
    if (ok) return i
  }
  throw new Error('no solution within maxnumber')
}
