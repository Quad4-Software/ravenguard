---
title: Architecture
description: Client resolution, filter stages, and upstream forwarding.
---

# Architecture

```text
Client -> reverse proxy (TLS termination) -> RavenGuard -> origin
```

RavenGuard applies application-layer controls after TLS termination. Volumetric DDoS mitigation belongs at the edge or CDN.

## Request pipeline

1. **Client IP** from trusted `X-Real-IP`, an `X-Forwarded-For` walk, or PROXY protocol
2. **IP / DNS / UA blocklists** loaded from files and reloaded on an interval
3. **Optional Q-Feeds cache** for malware IP and domain entries
4. **Rate limit** keyed by privacy client identity (hashed IP by default). Write methods cost more
5. **Protect** size limits, concurrency caps, attack signatures, and temp bans
6. **Detect** HTTP heuristics, short-window behavior, and optional proxy bot-score headers (skipped for WebSocket upgrades)
7. **Challenge or block**, otherwise **proxy** to the origin

WebSocket upgrades (`Connection: Upgrade` + `Upgrade: websocket`) still pass blocklists, feeds, health, attack signatures, rate limits, and protect. Detect scoring is skipped. When challenge is enabled, upgrades need an existing clearance cookie or they receive `403` (not an HTML challenge page).

Upstream forwarding sets `X-Real-IP` and rebuilds `X-Forwarded-For` from the resolved client IP. It does not append client-supplied prior values. Origin schemes may be `http`, `https`, `ws`, `wss`, or `unix` (`ws`/`wss` map to `http`/`https` for the transport).

## Packages

| Area | Package |
|------|---------|
| Entry point | `cmd/ravenguard` |
| Config load and flags | `internal/config` |
| Pipeline orchestration | `internal/pipeline` |
| Blocklists | `internal/blocklist` |
| Rate limiting | `internal/ratelimit` |
| Attack / DoS protect | `internal/protect` |
| Scanner and behavior detect | `internal/detect` |
| Challenge / PoW | `internal/challenge` |
| Upstream proxy | `internal/proxy` |
| Challenge and block UI | `internal/ui` |
| Privacy hashing | `internal/privacy` |
| Q-Feeds | `internal/qfeeds` |
| Sentry / GlitchTip | `internal/sentry` |
| Landlock + seccomp-bpf | `internal/sandbox` |

## Detection limits

Requests with known scanner User-Agents or missing browser headers are scored and may be challenged or blocked. Agents that set `navigator.webdriver` or skip interaction fail the challenge environment probe.

Agents that spoof a full browser profile and solve proof-of-work can pass. TLS JA3 is not available after the reverse proxy unless the proxy forwards reputation headers such as `CF-Bot-Score`, `X-Bot-Score`, or `X-JA4`.

## Trust modes

- `behind_proxy` refuses to start without `trusted_proxies`. Use this for the primary topology.
- `edge` is for deployments where RavenGuard is the first hop.

See [Deployment](./deployment.md) for PROXY protocol and real-IP header options.
