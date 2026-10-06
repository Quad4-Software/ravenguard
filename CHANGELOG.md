# Changelog

## Unreleased

### Added

- cgit forge path detection, including deep-nested repo trees and the
  non-virtual-root `?url=` query form. Selected with
  `[detect] forge_flavor` (`auto`, `gitea`, `forgejo`, `cgit`). Auto also
  covers flat `/{repo}/{cmd}` and one-level `/{group}/{repo}/{cmd}` cgit
  layouts and GitLab `/-/` routes.
- No-JS challenge fallback: the challenge page shows a "Continue without
  JavaScript" link to clients with a text-mode browser User-Agent, minting a
  bound clearance cookie. Scoring still applies after clearance. Toggle with
  `[challenge] no_js_fallback` (default on).
- Legacy `ray_id` columns in `waf_events` and `ml_samples` are renamed to
  `request_id` when the admin store opens an older database.

### Changed

- Ray ID is now Request ID across config keys (`request_id_label`,
  `request_id_header`), the response header (`X-RavenGuard-Request-ID`),
  challenge payloads, the agent protocol (`request.by_id`), event JSON, and
  the admin UI. The agent dispatch still accepts `request.by_ray` and `ray`
  payload fields from pre-rename peers, and the challenge POST accepts a `ray`
  field from cached pages.
- Dependencies updated: certmagic 0.25.6, coraza 3.8.1, modernc.org/sqlite
  1.60.1, zerossl, gjson, ncruces strftime, GitHub Actions pins, npm lockfile.

### Breaking

- Config keys `ui.ray_label` and `stealth.ray_header` are retired. Old keys
  are ignored. Env var `RG_STEALTH_RAY_HEADER` is now
  `RG_STEALTH_REQUEST_ID_HEADER`.
- `requestlog.Event` serializes `request_id` instead of `ray`. Webhook and
  API consumers must update.

### Notes

- vitest 5.0.3 and javascript-obfuscator 5.8.1 are held by the seven-day
  package maturity window (`minimumReleaseAge` in pnpm-workspace.yaml).
