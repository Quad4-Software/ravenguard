---
sidebar_position: 1
title: Getting started
description: Build RavenGuard and place it between a reverse proxy and an origin.
---

# Getting started

RavenGuard is an HTTP application guard. Topology:

```text
Client -> reverse proxy (TLS) -> RavenGuard -> origin
```

It reads the client IP from trusted proxy headers and forwards allowed requests to an HTTP, HTTPS, WebSocket, or unix-socket upstream.

## Requirements

- Go 1.26.6 or newer to build from source
- A reverse proxy that terminates TLS and forwards the client address
- An upstream origin on TCP (`http`/`https`/`ws`/`wss`) or a unix socket

## Build and run

```bash
git clone https://github.com/Quad4-Software/ravenguard.git
cd ravenguard
make build
./bin/ravenguard -config configs/ravenguard.toml
```

Set `upstream.url` and a production challenge secret:

```bash
./bin/ravenguard \
  -config /etc/ravenguard/ravenguard.toml \
  -upstream http://127.0.0.1:8000 \
  -challenge-secret "$RG_CHALLENGE_SECRET"
```

## Docker

```bash
cd deploy
docker compose up --build
```

The compose file builds RavenGuard, mounts sample config and blocklists, and proxies to a `whoami` origin on port `8080`.

## First checks

1. Set `trust.mode = "behind_proxy"` and list every trusted hop in `trust.trusted_proxies`.
2. Prefer `real_ip_header = "X-Real-IP"` when the proxy sets a single client address.
3. Set `RG_CHALLENGE_SECRET` (min 16 characters, not `change-me*`) before exposing the challenge path.
4. Keep `ui.test_mode` off outside local preview use.

## Next

- [Architecture](./architecture.md) for the request pipeline
- [Deployment](./deployment.md) for proxy and Docker layouts
- [Configuration](./configuration.md) for TOML, env, and flags
