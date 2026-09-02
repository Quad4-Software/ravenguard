import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  decodePayload,
  encodePayload,
  solveChallenge,
  verifyPBKDF2,
  verifySHA256,
  type Challenge,
} from '../src/protocol'

const fixtureDir = join(
  dirname(fileURLToPath(import.meta.url)),
  '../../../testdata/challenge',
)

describe('protocol parity', () => {
  it('matches sha256 golden fixture', async () => {
    const raw = JSON.parse(readFileSync(join(fixtureDir, 'sha256_v1.json'), 'utf8')) as {
      challenge: Challenge
      solution: string
      payload: string
    }
    const ok = await verifySHA256(
      raw.challenge.challenge,
      Number(raw.solution),
      raw.challenge.difficulty,
    )
    expect(ok).toBe(true)
    const sol = await solveChallenge(raw.challenge)
    expect(String(sol)).toBe(raw.solution)
    const decoded = decodePayload(raw.payload)
    expect(decoded.solution).toBe(raw.solution)
    expect(decoded.signature).toBe(raw.challenge.signature)
  })

  it('matches pbkdf2 golden fixture', async () => {
    const raw = JSON.parse(readFileSync(join(fixtureDir, 'pbkdf2_v1.json'), 'utf8')) as {
      challenge: Challenge
      solution: string
      payload: string
    }
    const iters = raw.challenge.params?.iterations ?? 1000
    const ok = await verifyPBKDF2(
      raw.challenge.challenge,
      raw.challenge.salt!,
      Number(raw.solution),
      raw.challenge.difficulty,
      iters,
    )
    expect(ok).toBe(true)
    const decoded = decodePayload(raw.payload)
    const round = encodePayload(decoded)
    expect(decodePayload(round).solution).toBe(raw.solution)
  })
})
