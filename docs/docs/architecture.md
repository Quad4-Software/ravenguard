---
title: Architecture
description: How RavenGuard resolves clients, filters abuse, and forwards to origin.
---

# Architecture

Primary path:

```text
Client -> reverse proxy (TLS termination) -> RavenGuard -> origin
```

RavenGuard owns application-layer controls after TLS ends. Volumetric DDoS still belongs at the edge or CDN.

## Request pipeline

Every request walks this ordered path:

1. **Client IP** from trusted `X-Real-IP`, an `X-Forwarded-For` walk, or PROXY protocol
2. **IP / DNS / UA blocklists** loaded from files and reloaded on an interval
3. **Optional Q-Feeds cache** for malware IP and domain intel
4. **Rate limit** keyed by a privacy-safe client identity (hashed IP by default). Write methods cost more
5. **Protect** size limits, concurrency shedding, attack signatures, and temp bans
6. **Detect** HTTP heuristics, short-window behavior, and optional proxy bot-score headers
7. **Challenge or block**, otherwise **proxy** to the origin

Upstream forwarding sets `X-Real-IP` and rebuilds `X-Forwarded-For` from the resolved client IP. It does not append onto client-spoofed prior values.

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

Scanners and scrapers with obvious User-Agents or missing browser headers are scored and challenged or blocked. Browser-automated agents that set `navigator.webdriver` or skip interaction fail the challenge environment probe.

Motivated agents that fully spoof a real browser and solve proof-of-work can still pass. TLS JA3 is not available after the reverse proxy unless the proxy forwards reputation headers such as `CF-Bot-Score`, `X-Bot-Score`, or `X-JA4`.

## Trust modes

- `behind_proxy` (recommended for the primary topology) refuses to start without `trusted_proxies`
- `edge` is for deployments where RavenGuard itself is the first hop

See [Deployment](./deployment.md) for PROXY protocol and real-IP header choices.
