/// <reference lib="webworker" />

import { verifyPBKDF2, verifySHA256, type Challenge } from '../protocol'

export type WorkerRequest = {
  id: number
  challenge: Challenge
  start: number
  end: number
}

export type WorkerResponse = {
  id: number
  found?: number
  done: boolean
  error?: string
}

async function scan(req: WorkerRequest): Promise<WorkerResponse> {
  const ch = req.challenge
  const iters = ch.params?.iterations ?? 10000
  try {
    for (let i = req.start; i <= req.end; i++) {
      let ok = false
      if (ch.algorithm === 'PBKDF2-SHA256') {
        if (!ch.salt) return { id: req.id, done: true, error: 'missing salt' }
        ok = await verifyPBKDF2(ch.challenge, ch.salt, i, ch.difficulty, iters)
      } else {
        ok = await verifySHA256(ch.challenge, i, ch.difficulty)
      }
      if (ok) return { id: req.id, found: i, done: true }
    }
    return { id: req.id, done: true }
  } catch (e) {
    return { id: req.id, done: true, error: e instanceof Error ? e.message : String(e) }
  }
}

self.onmessage = (ev: MessageEvent<WorkerRequest>) => {
  void scan(ev.data).then((res) => self.postMessage(res))
}
