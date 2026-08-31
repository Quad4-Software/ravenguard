# RavenGuard

> [!WARNING]
> This project is still alpha level software and being actively developed. Not ready for production use.

Application guard for HTTP origins sitting behind your reverse proxy.

**Typical topology:**

Client -> reverse proxy (TLS) -> RavenGuard -> origin

## Features

- Sits behind nginx, Caddy, Traefik, or similar (uses the real client IP your proxy sends)
- Forwards traffic to your app over HTTP or a unix socket
- Block bad IPs, hostnames, and User-Agents (lists reload without a restart)
- Slow down or stop abusive clients with rate limits
- Spot scanners, scrapers, and many AI crawlers before they hammer your app
- Soft DoS protection: limit how many requests run at once, cap request size, temp-ban repeat offenders
- Block common exploit probes in URLs (path tricks, injection-style junk)
- Optional browser check page (JavaScript puzzle) so bots have a harder time
- Keeps client IPs hashed in memory/logs by default for privacy-friendly ops
- Optional threat-intel feeds (Q-Feeds)
- Checks if your upstream app is healthy before sending traffic
- Optional Sentry / GlitchTip error reporting (panics, slog errors, optional upstream failures)
- Linux Landlock LSM + seccomp-bpf sandboxing (`try` / `best_effort` / `enforce`)
- Simple dark block/challenge pages, plus a local preview mode for testing
- Config with a TOML file, environment variables, or CLI flags

## Install / build from source

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

Site source lives in [`docs/`](docs/) (Docusaurus).

```bash
cd docs
pnpm install --frozen-lockfile
pnpm start
```

Requires Node.js 22+ and pnpm 11+.

## License

[0BSD](LICENSE).
