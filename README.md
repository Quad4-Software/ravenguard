# RavenGuard

> [!WARNING]
> Alpha software under active development. Not ready for production.

HTTP edge reverse proxy and application guard. RavenGuard can terminate TLS with automatic Let's Encrypt, route to multiple upstreams, enforce access gates, and run WAF-style controls:

```text
Client -> RavenGuard (:80/:443) -> origin(s)
```

It still works behind an external reverse proxy when you prefer that topology:

```text
Client -> reverse proxy (TLS) -> RavenGuard -> origin
```

## Features

- Edge TLS with static PEM files or automatic Let's Encrypt (HTTP-01 / TLS-ALPN-01, durable renewals)
- Multi-upstream host and path routing with live admin CRUD
- Per-route access gates: password, PIN, IP allowlist, header secret, User-Agent allowlist
- Optional placement behind nginx, Caddy, or Traefik with trusted proxy headers
- Proxies to HTTP, HTTPS, WebSocket (`ws`/`wss` URL aliases), or unix-socket upstreams
- IP, hostname, and User-Agent blocklists with periodic reload
- IP, User-Agent, and header allowlists that skip detect and challenge
- Per-client rate limits
- Heuristic detection for scanners, scrapers, and common AI crawler User-Agents
- Concurrency limits, request size caps, temporary bans for repeat offenders
- Blocks common path and query exploit probes
- Optional JavaScript proof-of-work challenge (`@quad4/ravenguard-widget`) with clearance cookie
- Adaptive PoW effort (SHA-256 / PBKDF2) from detect risk bands
- Embeddable form widget sharing the same protocol as the gate interstitial
- Optional admin control plane on a separate listen address (multi-user, argon2id, embedded SPA)
- WebSocket upgrades require an existing clearance cookie when challenge is enabled
- Client IPs hashed in memory and logs by default
- Optional Q-Feeds threat-intel integration
- Optional upstream health checks
- Optional Sentry / GlitchTip error reporting
- Linux Landlock LSM and seccomp-bpf sandbox (`try` / `best_effort` / `enforce`)
- Block and challenge HTML pages. Local UI preview via test mode
- Configured via TOML, environment variables, or CLI flags

## Build

Requires Go 1.26.6+.

```bash
git clone https://github.com/Quad4-Software/ravenguard.git
cd ravenguard
make build
./bin/ravenguard -config configs/ravenguard.toml
```

Docker:

```bash
cd deploy && docker compose up --build
```

## Docs

Docusaurus site in [`docs/`](docs/).

```bash
cd docs
pnpm install --frozen-lockfile
pnpm start
```

Requires Node.js 22+ and pnpm 11+.

## License

[0BSD](LICENSE).
