---
title: Deployment
description: Reverse proxy placement, Docker, and real-IP trust settings.
---

# Deployment

## Topology

### Edge (recommended when RavenGuard owns TLS)

```text
Client -> RavenGuard (:80 / :443) -> app
```

Point DNS A/AAAA records at the RavenGuard host. Open TCP 80 and 443 (and UDP 443 for QUIC). Use automatic Let's Encrypt:

```toml
[listen]
http = ":80"
https = ":443"

[tls]
mode = "acme"

[tls.acme]
email = "admin@example.com"
agree_tos = true
staging = true
storage_dir = "./data/certs"
hosts = ["app.example.com"]
http01 = true
tls_alpn01 = true
redirect_http = true

[trust]
mode = "edge"
```

Persist `storage_dir` across restarts. That directory holds the ACME account and certificates. Deleting it forces re-issue and can hit Let's Encrypt rate limits. Bring up with `staging = true`, then flip to production.

Use `trust.mode = "edge"` so RavenGuard ignores `X-Real-IP`, `X-Forwarded-For`, and related forwarded client headers. Client IP comes from the direct TCP peer only.

### Behind an external reverse proxy

```text
Client -> nginx / Caddy / Traefik -> RavenGuard -> app
```

```toml
[trust]
mode = "behind_proxy"
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128"]
real_ip_header = "X-Real-IP"
proto_header = "X-Forwarded-Proto"
proxy_protocol = false
```

`proto_header` sets the clearance cookie Secure flag when TLS ends at the proxy.

Override the CIDR list with `RG_TRUSTED_PROXIES` (comma-separated). Keep the [admin control plane](./admin.md) on a private bind (default `127.0.0.1:9090`) or behind a locked-down reverse proxy path. Never publish it like the public guard port.

## Reverse proxy snippets

Forward `X-Real-IP`, `X-Forwarded-For`, and `X-Forwarded-Proto`. Pass WebSocket `Upgrade` and `Connection` headers. Point RavenGuard `trust.trusted_proxies` (or `RG_TRUSTED_PROXIES`) at the proxy addresses only.

### nginx

```nginx
upstream ravenguard {
  server 127.0.0.1:8080;
}

server {
  listen 443 ssl http2;
  server_name app.example.com;

  location / {
    proxy_pass http://ravenguard;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
  }
}

map $http_upgrade $connection_upgrade {
  default upgrade;
  '' close;
}
```

### Caddy

```caddy
app.example.com {
  reverse_proxy 127.0.0.1:8080 {
    header_up X-Real-IP {remote_host}
    header_up X-Forwarded-For {remote_host}
    header_up X-Forwarded-Proto {scheme}
  }
}
```

Caddy forwards WebSocket upgrades by default when the client requests them.

### Traefik

```yaml
http:
  routers:
    app:
      rule: Host(`app.example.com`)
      entryPoints: [websecure]
      service: ravenguard
      tls: {}
  services:
    ravenguard:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:8080
        passHostHeader: true
```

Traefik sets `X-Forwarded-*` for trusted hops. Ensure RavenGuard `trusted_proxies` matches the Traefik source addresses. For WebSockets, use an entrypoint that allows upgrades (default HTTP routers do).

## Binary

```bash
make build
./bin/ravenguard -config /etc/ravenguard/ravenguard.toml \
  -upstream http://127.0.0.1:8000 \
  -challenge-secret "$RG_CHALLENGE_SECRET"
```

| Path | Purpose |
|------|---------|
| `/usr/local/bin/ravenguard` | Binary |
| `/etc/ravenguard/ravenguard.toml` | Config |
| `/etc/ravenguard/blocklists/` | IP, DNS, and UA lists |
| `/var/lib/ravenguard/certs/` | ACME storage (when `tls.mode = acme`) |

## Docker Compose

Use [`deploy/docker-compose.yml`](https://github.com/Quad4-Software/ravenguard/blob/main/deploy/docker-compose.yml):

```bash
cd deploy
docker compose up --build
```

Mount config and blocklists. Set `RG_CHALLENGE_SECRET` and `QFEEDS_API_TOKEN` when needed. Point `upstream.url` at the app service. The sample stack exposes `8080`, optional `80`/`443` for edge ACME, and TCP/UDP `8443` for manual TLS or QUIC. The `certs-data` volume is ACME renewal memory.

The compose file enables Landlock and in-process seccomp-bpf via `[sandbox]` (default `best_effort`), drops all capabilities, sets `no-new-privileges`, mounts a read-only root with `/tmp` tmpfs, and applies [`deploy/seccomp-ravenguard.json`](https://github.com/Quad4-Software/ravenguard/blob/main/deploy/seccomp-ravenguard.json) so the container seccomp profile allows `landlock_*` and `seccomp`.

Override with `RG_SANDBOX_MODE=try` or `enforce` as needed. Hosts without Landlock still start under `try` / `best_effort`.

When adding upstreams on new TCP ports from the admin panel under `sandbox.mode = enforce`, either restart after the change or pre-open ports with `[sandbox.landlock] connect_tcp`. Prefer `best_effort` or `try` for dynamic routing during bring-up.

## PROXY protocol and real IP

Set `trust.mode = "behind_proxy"`, list every hop in `trust.trusted_proxies` (or `RG_TRUSTED_PROXIES`), and choose one of:

- `trust.real_ip_header = "X-Real-IP"` (one trusted hop)
- `trust.real_ip_header = "X-Forwarded-For"` (rightmost untrusted hop)
- `trust.proxy_protocol = true` (PROXY protocol v1/v2 from the trusted peer)

With `trust.mode = "edge"`, forwarded headers and PROXY protocol client addresses are not used for trust decisions. Prefer edge when RavenGuard terminates TLS directly.

Untrusted forwarded headers without a tight `trusted_proxies` list allow client IP spoofing. RavenGuard will not start in `behind_proxy` mode without that list.

## Unix upstream

```toml
[upstream]
url = "unix:///var/run/app.sock"
connect_timeout = "5s"
response_header_timeout = "30s"
```

## HTTPS and WebSocket origins

Point `upstream.url` at `https://` when RavenGuard should speak TLS to the app. Use `ws://` / `wss://` as aliases for the same host when documenting WebSocket apps (they map to `http` / `https` for the reverse proxy).

Ensure the reverse proxy forwards `Upgrade` and `Connection` for WebSocket paths. When challenge is enabled, clients must obtain a clearance cookie over a normal HTTP(S) page load before the WebSocket handshake will be proxied.

## Upstream health

```toml
[upstream.health]
enabled = true
path = "/healthz"
interval = "10s"
timeout = "3s"
```

## Production checklist

- Replace the example challenge secret
- Keep `ui.test_mode = false`
- Keep `privacy.hash_client_ip = true` unless raw addresses are required
- Store blocklist files on durable storage
- Confirm the proxy forwards `X-Forwarded-Proto` (or the configured proto header)
