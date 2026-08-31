---
title: Deployment
description: Place RavenGuard behind a reverse proxy and in front of your origin.
---

# Deployment

## Topology

Terminate TLS at your reverse proxy, forward to RavenGuard on loopback or a private network, then to the origin:

```text
Client -> nginx / Caddy / Traefik -> RavenGuard -> app
```

Publish TCP `80`/`443` and UDP `443` on the reverse proxy, not necessarily on RavenGuard itself.

Set:

```toml
[trust]
mode = "behind_proxy"
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128"]
real_ip_header = "X-Real-IP"
proto_header = "X-Forwarded-Proto"
proxy_protocol = false
```

Use `proto_header` so clearance cookies get the Secure flag when TLS ends at the proxy.

## Binary

```bash
make build
./bin/ravenguard -config /etc/ravenguard/ravenguard.toml \
  -upstream http://127.0.0.1:8000 \
  -challenge-secret "$RG_CHALLENGE_SECRET"
```

Suggested layout:

| Path | Purpose |
|------|---------|
| `/usr/local/bin/ravenguard` | Binary |
| `/etc/ravenguard/ravenguard.toml` | Config |
| `/etc/ravenguard/blocklists/` | IP, DNS, and UA lists |

## Docker Compose

Use [`deploy/docker-compose.yml`](https://github.com/Quad4-Software/ravenguard/blob/main/deploy/docker-compose.yml):

```bash
cd deploy
docker compose up --build
```

Mount config and blocklists, set `RG_CHALLENGE_SECRET` and `QFEEDS_API_TOKEN` when needed, and point `upstream.url` at your app service. The sample stack exposes RavenGuard on `8080` and includes TCP/UDP `8443` for optional TLS or QUIC listeners.

The compose file enables Landlock and in-process seccomp-bpf via `[sandbox]` (default `best_effort`), drops all capabilities, sets `no-new-privileges`, mounts a read-only root with `/tmp` tmpfs, and applies [`deploy/seccomp-ravenguard.json`](https://github.com/Quad4-Software/ravenguard/blob/main/deploy/seccomp-ravenguard.json) so the container seccomp profile allows `landlock_*` and `seccomp` for the in-process filters.

Override with `RG_SANDBOX_MODE=try` or `enforce` as needed. Host kernels without Landlock still start under `try` / `best_effort`.

## PROXY protocol and real IP

Behind a load balancer, set `trust.mode = "behind_proxy"`, list every hop in `trust.trusted_proxies`, and choose one of:

- `trust.real_ip_header = "X-Real-IP"` (recommended for one trusted hop)
- `trust.real_ip_header = "X-Forwarded-For"` (rightmost untrusted hop)
- `trust.proxy_protocol = true`

Mixing untrusted forwarded headers without a tight `trusted_proxies` list lets clients spoof identity. RavenGuard will not start in `behind_proxy` mode without that list.

## Unix upstream

Forward to a local socket instead of TCP:

```toml
[upstream]
url = "unix:///var/run/app.sock"
connect_timeout = "5s"
response_header_timeout = "30s"
```

## Upstream health

Optional active checks before sending traffic:

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
- Hash client IPs unless you have a reason not to
- Reload-friendly blocklist paths on durable storage
- Confirm the proxy forwards `X-Forwarded-Proto` (or your configured proto header)
