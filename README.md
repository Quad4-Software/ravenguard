# RavenGuard

HTTP web application firewall and reverse proxy. RavenGuard terminates TLS, routes traffic to upstreams, and enforces rate limits, blocklists, and heuristic bot detection with a proof-of-work challenge.

## Features

- Host and path routing to multiple upstreams, with automatic Let's Encrypt, static PEM, or self-signed certificates
- Bot and scanner scoring: request-shape signals, behavior bursts, UA tables, and verified-crawler rDNS checks
- Forge-aware scoring for Gitea, Forgejo, GitLab, cgit, and Sourcehut paths. Git smart HTTP passes through untouched
- Proof-of-work challenge with invisible and interactive gates, plus a no-JS fallback for text-mode browsers (Lynx, w3m, Links, Dillo, NetSurf)
- Per-route access gates by password, PIN, IP, header, or User-Agent
- Optional Coraza / OWASP CRS engine, per-route OpenAPI schema gates, semantic payload analysis, and pure-Go ML scoring
- Hub-and-proxy fleet mode over Nebula overlay, with threat sharing and STIX, CSV, AbuseIPDB, and MISP ingest
- Server-rendered admin UI, request log lookup by Request ID, Linux Landlock and seccomp sandbox

## Install

Requires Go 1.26.6+.

```bash
git clone https://github.com/Quad4-Software/ravenguard.git
cd ravenguard
make build
```

Docker:

```bash
cd deploy && docker compose up --build
```

Published image: `ghcr.io/quad4-software/ravenguard:edge`

## Quick start

```bash
./bin/ravenguard -config configs/ravenguard.toml
```

Process modes: `all` (default), `hub`, or `proxy`, set by the first CLI argument or `RG_MODE`. The admin UI is opt-in with `-admin-enabled`, bound to `127.0.0.1:9090` by default.

## Docs

Docusaurus site under [docs/](docs/). See [getting started](docs/docs/intro.md) and the [configuration reference](docs/docs/configuration.md).

## License

[QSL-1.0-0BSD](LICENSE).
