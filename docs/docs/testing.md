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

`make test` runs the Go test suite across packages. Coverage includes config loading, blocklists, proof-of-work, pipeline allow/block/challenge paths, rate limits, high-404 handling, and UI rendering.

## Fuzz targets

Fuzz tests live under:

- `internal/iputil`
- `internal/blocklist`
- `internal/challenge`
- `internal/detect`
- `internal/qfeeds`

`make fuzz` runs short timed fuzz sessions for the packaged targets.

## Local UI previews

Enable test mode:

```bash
./bin/ravenguard -config configs/ravenguard.toml -test-mode
```

Then open `/_rg/test` for links to challenge, block, rate-limit, upstream, and error pages. Leave test mode off in production.

## Suggested manual checks

1. Hit the origin through RavenGuard with a normal browser and confirm clearance after challenge (if `mode = "always"` or detect scores trip)
2. Confirm blocked UA / IP lists deny before the origin
3. Verify `X-Real-IP` / proto headers from your proxy produce Secure cookies on HTTPS sites
4. Overload a client against rate limits and confirm challenge or reject behavior matches config
5. Toggle upstream health and confirm failed origins fail closed according to your expectations
