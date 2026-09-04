import { spawn } from 'node:child_process'
import http from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(__dirname, '..')
const bin = path.join(root, 'bin', 'ravenguard')

const children = []

function waitPort(port, ms = 60_000) {
  const start = Date.now()
  return new Promise((resolve, reject) => {
    const tick = () => {
      const req = http.get({ host: '127.0.0.1', port, path: '/', timeout: 1000 }, (res) => {
        res.resume()
        resolve()
      })
      req.on('error', () => {
        if (Date.now() - start > ms) reject(new Error(`timeout waiting for :${port}`))
        else setTimeout(tick, 250)
      })
    }
    tick()
  })
}

function start(cmd, args, env = {}) {
  const child = spawn(cmd, args, {
    cwd: root,
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.stdout.on('data', (d) => process.stdout.write(`[${args[0] || cmd}] ${d}`))
  child.stderr.on('data', (d) => process.stderr.write(`[${args[0] || cmd}] ${d}`))
  child.on('exit', (code) => {
    if (code && code !== 0) console.error(`child exited ${code}: ${cmd} ${args.join(' ')}`)
  })
  children.push(child)
  return child
}

function shutdown() {
  for (const c of children) {
    try {
      c.kill('SIGTERM')
    } catch {
      /* ignore */
    }
  }
}

process.on('SIGINT', () => {
  shutdown()
  process.exit(0)
})
process.on('SIGTERM', () => {
  shutdown()
  process.exit(0)
})

start(process.execPath, [path.join(__dirname, 'upstream.mjs')])

const fixtures = [
  ['pass.toml', 18080],
  ['attack.toml', 18081],
  ['captcha.toml', 18082],
  ['refuse.toml', 18083],
  ['stress.toml', 18084],
]

for (const [name] of fixtures) {
  start(bin, ['-config', path.join(__dirname, 'fixtures', name)])
}

await waitPort(18000)
for (const [, port] of fixtures) {
  await waitPort(port)
}

console.log('e2e harness ready')

// Keep alive until killed by Playwright.
await new Promise(() => {})
