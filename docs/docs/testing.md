---
title: Testing
description: Unit tests, fuzz targets, and local UI preview mode.
---

# Testing

## Automated tests

```bash
make test
make fuzz
```

`make test` runs the Go test suite. Coverage includes config loading, blocklists, proof-of-work, pipeline allow/block/challenge paths, rate limits, high-404 handling, and UI rendering.

## Fuzz targets

- `internal/iputil`
- `internal/blocklist`
- `internal/challenge`
- `internal/detect`
- `internal/qfeeds`

`make fuzz` runs short timed fuzz sessions for the packaged targets.

## Local UI previews

```bash
./bin/ravenguard -config configs/ravenguard.toml -test-mode
```

Open `/_rg/test` for challenge, block, rate-limit, upstream, and error page previews. Leave test mode off in production.

## Manual checks

1. Request the origin through RavenGuard with a normal browser. Confirm clearance after challenge when `mode = "always"` or detect scores trip.
2. Confirm blocked UA / IP lists deny before the origin.
3. Verify `X-Real-IP` / proto headers from the proxy produce Secure cookies on HTTPS sites.
4. Exceed rate limits and confirm challenge or reject behavior matches config.
5. Toggle upstream health and confirm failed origins fail closed as configured.
