---
title: Privacy
description: Client IP hashing, request ID control, and retention.
---

# Privacy

RavenGuard always hashes client IPs for bind keys, rate limits, behavior state, and logs. There is no opt-out.

## Defaults

```toml
[privacy]
# ip_hash_secret = ""   # empty derives from challenge.secret
log_ip = "hash"         # off | hash
request_ids = true      # expose Request IDs on pages, headers, and events
retention = "30m"       # in-memory client state
waf_events_ttl = "336h" # stored deny events, 14 days
# privacy_notice_url = "https://example.com/privacy"
```

With hashing on:

- Rate limits, 404 tracking, behavior windows, and clearance binding use a hashed key
- Logs use a hash instead of the raw address when log_ip is hash
- In-memory soft state is bounded by retention
- Fleet threat sharing uses the same bind hash as the ban key when key_type is bind (keep ip_hash_secret / challenge secret aligned via fleet defaults). Admin threat listings show redacted keys only. Raw IP share (key_type ip) is opt-in for operators who accept that risk.
- Threat intel STIX/CSV export omits raw IPs unless export_raw_ip is enabled. Bind, UA, domain, and JA4 indicators still export. See [Threat intel](./threatintel.md).

## Request IDs

Every response carries an opaque Request ID in the X-RavenGuard-Request-ID header, on rendered pages, and in stored events so operators can correlate and look requests up in the admin Requests view. Set `request_ids = false` to expose nothing: no header, no page field, and no ID on stored events. Challenge binding still uses the internal identifier.

Stored deny events (waf_events) are purged after waf_events_ttl, default 14 days.

## Secrets

If ip_hash_secret is empty, hashing material is derived from challenge.secret. In production:

1. Set a strong RG_CHALLENGE_SECRET
2. Optionally set RG_PRIVACY_IP_HASH_SECRET to rotate hashes independently of challenge cookies

Rotating either secret invalidates derived identities and clearance cookies that depended on them.

## Log IP modes

| Mode | Behavior |
|------|----------|
| off | Do not log client IP material |
| hash | Log the privacy hash (default) |

## Challenge page notice

```toml
[privacy]
privacy_notice_url = "https://example.com/privacy"
```

When set, the challenge page includes a link to that URL.

## Env vars

- RG_PRIVACY_IP_HASH_SECRET
- RG_PRIVACY_REQUEST_IDS
- RG_PRIVACY_LOG_IP
- RG_PRIVACY_NOTICE_URL
