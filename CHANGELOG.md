# Changelog

## Unreleased

### Added

- Web Bot Auth: signed automated traffic is verified per the IETF
  webbotauth draft (RFC 9421 HTTP Message Signatures over Signature-Agent
  ed25519 key directories). Verified agents get the wba_verified reason and
  skip ai_ua scoring unless the policy is block or pay. Invalid signatures
  add web_bot_auth.spoof_score. Key fetches are HTTPS only and cached.
- AI crawler policy: `[detect] ai_crawler_policy` is allow, challenge,
  block, or pay. pay returns HTTP 402 with an x402 payment document built
  from `[detect.ai_pay]`, and validates PAYMENT-SIGNATURE / X-PAYMENT
  headers through an optional facilitator endpoint.
- robots.txt AI declarations: `[site] robots_ai` emits a Content-Signal
  line (signal) plus Disallow groups for known AI training crawlers
  (disallow). `[site] rsl_file` serves /.well-known/rsl.xml and adds a
  License: line. `[site] llms_file` serves /llms.txt.
- Request IDs can be disabled with `[privacy] request_ids = false`,
  removing the header, page field, and stored event ID.
- WAF event retention is configurable via `[privacy] waf_events_ttl`
  (default 14 days).
- 2026 UA table refresh: hosted agent browsers and newer AI indexers.
- cgit forge path detection, including deep-nested repo trees and the
  non-virtual-root `?url=` query form. Selected with
  `[detect] forge_flavor` (`auto`, `gitea`, `forgejo`, `cgit`). Auto also
  covers flat `/{repo}/{cmd}` and one-level `/{group}/{repo}/{cmd}` cgit
  layouts and GitLab `/-/` routes.
- No-JS challenge fallback: the challenge page shows a "Continue without
  JavaScript" link to clients with a text-mode browser User-Agent. Scoring
  still applies after clearance. Toggle with `[challenge] no_js_fallback`
  (default on).
- Legacy `ray_id` columns in `waf_events` and `ml_samples` are renamed to
  `request_id` when the admin store opens an older database.

### Changed

- Client IPs and bind keys are always hashed. The hash_client_ip option is
  removed and `privacy.log_ip` accepts off or hash only.
- The no-JS fallback is now a timed two-hop flow: the noscript page issues a
  meta-refresh token bound to client and path that must age
  `[challenge] no_js_delay` (default 3s) before it redeems for clearance.
- Landlock net rules keep UDP send unrestricted when a QUIC listener is
  configured. Previously a handled connect_send_udp right with no matching
  rule denied every reply and HTTP/3 never completed a handshake.
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
- `privacy.hash_client_ip` is removed (ignored if present) and
  `privacy.log_ip = "full"` is rejected. IP material is always hashed.
- `detect.web_bot_auth` verification is on by default. Set
  `enabled = false` to disable signature checks.

### Notes

- vitest 5.0.3 and javascript-obfuscator 5.8.1 are held by the seven-day
  package maturity window (`minimumReleaseAge` in pnpm-workspace.yaml).
