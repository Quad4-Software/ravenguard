---
sidebar_position: 1
title: Getting started
description: Build RavenGuard and place the WAF in front of your origin.
---

# Getting started

RavenGuard is an HTTP Web Application Firewall and reverse proxy.

```text
Client -> RavenGuard (:80/:443) -> origin(s)
```

Behind an external reverse proxy:

```text
Client -> reverse proxy (TLS) -> RavenGuard -> origin
```

Fleet mode separates management from public edges:

```text
Public clients -> ravenguard proxy
Overlay        -> ravenguard hub
```

It terminates TLS, routes by host and path, runs the WAF pipeline, applies optional access gates, then forwards to HTTP, HTTPS, WebSocket, or unix-socket upstreams.

Optional [admin control plane](./admin.md): separate listen address, multi-user auth, live route editing, proxy enrollment, and an embedded SPA.

## Requirements

- Go 1.26.6 or newer to build from source
- For edge TLS: public DNS pointing at this host and open ports 80/443
- Or a reverse proxy that terminates TLS and forwards the client address
- An upstream origin on TCP or a unix socket
- For fleet mode: a private overlay (Tailscale, Netbird, or WireGuard) for the hub

## Build and run

```bash
git clone https://github.com/Quad4-Software/ravenguard.git
cd ravenguard
make build
./bin/ravenguard -config configs/ravenguard.toml
```

| Mode | Role |
|------|------|
| all (default) | Combined WAF and optional admin |
| hub | Admin SPA, SQLite, agent accept |
| proxy | Public WAF and outbound agent to the hub |

Set the mode with the first CLI argument (`ravenguard hub`) or `RG_MODE` when the process manager cannot set a custom command:

```bash
RG_MODE=hub
RG_CONFIG=/config/hub.toml
```

```bash
RG_MODE=proxy
RG_CONFIG=/config/ravenguard.toml
RG_AGENT_HUB_URL=http://ravenguard-hub:8080
RG_AGENT_TOKEN=...
RG_AGENT_HUB_PUBKEY=...
```

Point at an upstream and a production challenge secret:

```bash
./bin/ravenguard \
  -config /etc/ravenguard/ravenguard.toml \
  -upstream http://127.0.0.1:8000 \
  -challenge-secret "$RG_CHALLENGE_SECRET"
```

## Local HTTPS with self-signed TLS

For development without Let's Encrypt, set `tls.mode = "selfsigned"`, enable `listen.https`, and keep `trust.mode = "edge"`:

```toml
[listen]
http = ":8080"
https = ":8443"

[tls]
mode = "selfsigned"

[tls.selfsigned]
storage_dir = "./data/selfsigned"
hosts = ["localhost", "127.0.0.1"]
validity = "365d"
```

Or write PEM files and use `tls.mode = "files"`:

```bash
./bin/ravenguard cert generate -hosts localhost,127.0.0.1 -cert ./certs/fullchain.pem -key ./certs/privkey.pem
```

Browsers will warn on self-signed certificates until you trust them locally.

## Docker

```bash
cd deploy
docker compose up --build
```

The compose file builds RavenGuard, mounts sample config and blocklists, and proxies to a whoami origin on port 8080.

## First checks

1. Set `trust.mode` to `behind_proxy` with every trusted hop in `trusted_proxies`, or use `edge` when RavenGuard owns TLS.
2. Prefer `real_ip_header = "X-Real-IP"` when the proxy sets a single client address.
3. Set `RG_CHALLENGE_SECRET` (min 16 characters, not a `change-me` placeholder) before exposing the challenge path.
4. Keep `ui.test_mode` off outside local preview.
5. For fleet installs, bind the hub to an overlay IP only and enroll proxies from the Proxies UI.

## Next

- [Architecture](./architecture.md) for the request pipeline and fleet topology
- [Deployment](./deployment.md) for proxy, Docker, and hub layouts
- [Admin](./admin.md) for the control plane, agents, and Move services
- [Configuration](./configuration.md) for TOML, env, and flags
