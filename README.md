# RavenGuard

> [!WARNING]
> Alpha software under active development. Not ready for production.

HTTP application guard for HTTP, HTTPS, and WebSocket origins. Place it between a reverse proxy and the origin:

```text
Client -> reverse proxy (TLS) -> RavenGuard -> origin
```

## Features

- Runs behind nginx, Caddy, Traefik, or similar. Uses the client IP from trusted proxy headers
- Proxies to HTTP, HTTPS, WebSocket (`ws`/`wss` URL aliases), or unix-socket upstreams
- IP, hostname, and User-Agent blocklists with periodic reload
- Per-client rate limits
- Heuristic detection for scanners, scrapers, and common AI crawler User-Agents
- Concurrency limits, request size caps, temporary bans for repeat offenders
- Blocks common path and query exploit probes
- Optional JavaScript proof-of-work challenge with clearance cookie
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
