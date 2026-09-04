# RavenGuard

HTTP Web Application Firewall and reverse proxy. RavenGuard sits in front of your origin, terminates TLS, routes traffic, and enforces application-layer controls.

```text
Client -> RavenGuard (:80/:443) -> origin(s)
```

Behind an external reverse proxy:

```text
Client -> reverse proxy (TLS) -> RavenGuard -> origin
```

Fleet mode splits management and edge:

```text
Public clients -> ravenguard proxy
Overlay        -> ravenguard hub
```

## Features

- Automatic Let's Encrypt, static PEM, or self-signed certificates
- Host and path routing to multiple upstreams
- Hub and proxy fleet with live admin cutover
- Optional connector tunnels for private origins
- Blocklists, rate limits, attack filters, and temp bans
- Fleet threat sharing plus open TI export/ingest (STIX, CSV, AbuseIPDB, MISP)
- Optional Coraza / OWASP CRS engine and per-route OpenAPI schema gates
- Optional semantic payload analysis and pure-Go ML scoring (shadow by default, FP-gated enforce)
- Ray ID request lookup in the admin UI
- Scanner and crawler detection with optional proof-of-work challenge
- Per-route access gates (password, PIN, IP, header, User-Agent)
- Optional admin control plane with embedded SPA
- Linux Landlock and seccomp sandbox

Full capability list and knobs live in the [docs](docs/).

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

Published image:

```bash
docker pull ghcr.io/quad4-software/ravenguard:edge
```

## Quick start

```bash
./bin/ravenguard -config configs/ravenguard.toml
```

Process modes: all (default), hub, proxy, or connector via the first CLI argument or RG_MODE.

See [Getting started](docs/docs/intro.md) and [Configuration](docs/docs/configuration.md).

## Docs

Docusaurus site under [docs/](docs/).

```bash
cd docs
pnpm install --frozen-lockfile
pnpm start
```

Requires Node.js 22+ and pnpm 11+.

## License

[0BSD](LICENSE).
