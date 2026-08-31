---
sidebar_position: 1
title: Getting started
description: Install RavenGuard and put it between your reverse proxy and origin.
---

# Getting started

RavenGuard is an application guard for HTTP origins. Typical topology:

```text
Client -> reverse proxy (TLS) -> RavenGuard -> origin
```

It sits behind nginx, Caddy, Traefik, or a similar edge, uses the real client IP your proxy sends, and forwards allowed traffic to your app over HTTP or a unix socket.

## Requirements

- Go 1.26.6 or newer to build from source
- A reverse proxy that terminates TLS and forwards the client address
- An upstream origin listening on TCP or a unix socket

## Build and run

```bash
git clone https://github.com/Quad4-Software/ravenguard.git
cd ravenguard
make build
./bin/ravenguard -config configs/ravenguard.toml
```

Point `upstream.url` at your app and set a production challenge secret:

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

The compose file builds RavenGuard, mounts an example config and blocklists, and proxies to a sample `whoami` origin on port `8080`.

## First checks

1. Confirm `trust.mode = "behind_proxy"` and list every trusted hop in `trust.trusted_proxies`.
2. Prefer `real_ip_header = "X-Real-IP"` when the proxy sets a single client address.
3. Set `RG_CHALLENGE_SECRET` (min 16 characters, not `change-me*`) before exposing the challenge path.
4. Leave `ui.test_mode` off in production. Use it locally to preview challenge and block pages.

## What to read next

- [Architecture](./architecture.md) for the request pipeline
- [Deployment](./deployment.md) for proxy and Docker layouts
- [Configuration](./configuration.md) for the full TOML and env surface
