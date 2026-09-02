---
title: Architecture
description: Client resolution, filter stages, and upstream forwarding.
---

# Architecture

```text
Client -> RavenGuard (TLS / ACME) -> WAF + access -> origin(s)
```

Or behind an external terminator:

```text
Client -> reverse proxy (TLS termination) -> RavenGuard -> origin
```

RavenGuard applies application-layer controls at the HTTP layer. Volumetric DDoS mitigation belongs at the edge or CDN.

## Request pipeline

1. **ACME HTTP-01** at `/.well-known/acme-challenge/` (bypasses WAF)
2. **Optional HTTP to HTTPS redirect** when edge ACME is enabled
3. **Client IP** from `RemoteAddr`, trusted `X-Real-IP`, an `X-Forwarded-For` walk, or PROXY protocol
4. **IP / DNS / UA blocklists** loaded from files and reloaded on an interval
5. **Optional Q-Feeds cache** for malware IP and domain entries
6. **Rate limit** keyed by privacy client identity (hashed IP by default). Write methods cost more
7. **Protect** size limits, concurrency caps, attack signatures, and temp bans
8. **Detect** HTTP heuristics, short-window behavior, and optional proxy bot-score headers (skipped for WebSocket upgrades and allowlisted clients)
9. **Challenge or block** (skipped when the client matches an IP, User-Agent, or header allowlist)
10. **Access policy** (password, PIN, IP allowlist, header, User-Agent) when attached to the matched route
11. **Route** by host + path prefix to an upstream, otherwise the default TOML upstream

WebSocket upgrades (`Connection: Upgrade` + `Upgrade: websocket`) still pass blocklists, feeds, health, attack signatures, rate limits, and protect. Detect scoring is skipped. When challenge is enabled, upgrades need an existing clearance cookie or they receive `403` (not an HTML challenge page), unless the client is allowlisted. Access policies also apply to WebSocket upgrades.

Upstream forwarding sets `X-Real-IP` and rebuilds `X-Forwarded-For` from the resolved client IP. It does not append client-supplied prior values. Origin schemes may be `http`, `https`, `ws`, `wss`, or `unix` (`ws`/`wss` map to `http`/`https` for the transport).

## Packages

| Area | Package |
|------|---------|
| Entry point | `cmd/ravenguard` |
| Config load and flags | `internal/config` |
| Pipeline orchestration | `internal/pipeline` |
| Multi-upstream router | `internal/router` |
| Access gates | `internal/access` |
| ACME / Let's Encrypt | `internal/tlsacme` |
| Blocklists | `internal/blocklist` |
| Allowlists | `internal/allowlist` |
| Rate limiting | `internal/ratelimit` |
| Attack / DoS protect | `internal/protect` |
| Scanner and behavior detect | `internal/detect` |
| Challenge / PoW protocol v1 | `internal/challenge` |
| Challenge widget (`@quad4/ravenguard-widget`) | `packages/widget` |
| Upstream proxy | `internal/proxy` |
| Challenge and block UI | `internal/ui` |
| Privacy hashing | `internal/privacy` |
| Q-Feeds | `internal/qfeeds` |
| Sentry / GlitchTip | `internal/sentry` |
| Landlock + seccomp-bpf | `internal/sandbox` |
| Admin control plane | `internal/admin`, `packages/admin` |
## Detection limits

Requests with known scanner or AI User-Agents or missing browser headers are scored and may be challenged or blocked. Agents that set `navigator.webdriver`, expose Playwright/Puppeteer/Selenium globals, look headless, or skip interaction fail the challenge environment probe.

Agents that spoof a full browser profile and solve proof-of-work can pass. TLS JA3 is not available after the reverse proxy unless the proxy forwards reputation headers such as `CF-Bot-Score`, `X-Bot-Score`, or `X-JA4`.

## Trust modes

- `edge` is for deployments where RavenGuard is the first hop (including ACME TLS).
- `behind_proxy` refuses to start without `trusted_proxies`. Use this when an external proxy terminates TLS.

See [Deployment](./deployment.md) for PROXY protocol and real-IP header options.
