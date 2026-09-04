---
title: Testing
description: Unit tests, fuzz targets, Playwright e2e, and local UI preview mode.
---

# Testing

## Automated tests

```bash
make test
make fuzz
make e2e
```

make test runs the Go test suite plus widget and admin Vitest suites. Coverage includes config loading, blocklists, proof-of-work, gate selection, pipeline allow/block/challenge paths, rate limits, high-404 handling, and UI rendering.

make e2e builds RavenGuard and runs the Playwright suite under e2e/ against a live binary (invisible and attack gates, stub captcha, automation refusal).

## Fuzz targets

- internal/iputil
- internal/blocklist
- internal/challenge
- internal/detect
- internal/qfeeds
- internal/faststr
- internal/requestlog
- internal/bodybuf

make fuzz runs short timed fuzz sessions for the packaged targets.

## Playwright e2e

```bash
make build
pnpm --dir e2e install
pnpm --dir e2e exec playwright install chromium firefox webkit
make e2e
```

Happy-path specs use challenge.env_probe = "off" so Playwright can obtain clearance. Refusal specs use env_probe = "on" and assert automation markers are rejected.

## Local UI previews

```bash
./bin/ravenguard -config configs/ravenguard.toml -test-mode
```

Open /_rg/test for challenge, block, rate-limit, upstream, and error page previews. Leave test mode off in production.

## Manual checks

1. Request the origin through RavenGuard with a normal browser. Confirm invisible auto-clearance when mode is always or detect scores trip at low risk.
2. Set mode to attack and confirm the visible checkbox gate (and captcha when enabled).
3. Confirm blocked UA / IP lists deny before the origin.
4. Verify X-Real-IP / proto headers from the proxy produce Secure cookies on HTTPS sites.
5. Exceed rate limits and confirm challenge or reject behavior matches config.
6. Toggle upstream health and confirm failed origins fail closed as configured.
7. With challenge enabled, open the site in a browser first, then confirm a WebSocket upgrade succeeds with the clearance cookie and fails with 403 without it.
8. Confirm https:// (or wss://) upstream URLs reach a TLS origin when configured.
9. On a hub, ingest a sample CSV from the Threat intel page and confirm the ledger revision advances and online proxies receive the overlay.
