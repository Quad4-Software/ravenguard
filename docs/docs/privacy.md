---
title: Privacy
description: Client IP hashing, log redaction, and retention.
---

# Privacy

By default, RavenGuard hashes client IPs for rate limits, behavior state, and logs.

## Defaults

```toml
[privacy]
hash_client_ip = true
# ip_hash_secret = ""   # empty derives from challenge.secret
log_ip = "hash"         # off | hash | full
retention = "30m"
# privacy_notice_url = "https://example.com/privacy"
```

With hashing on:

- Rate limits, 404 tracking, behavior windows, and clearance binding use a hashed key
- Logs use a hash instead of the raw address when `log_ip = "hash"`
- In-memory soft state is bounded by `retention`
- Fleet threat sharing uses the same bind hash as the ban key when `key_type=bind` (keep `ip_hash_secret` / challenge secret aligned via fleet defaults). Admin threat listings show redacted keys only. Raw IP share (`key_type=ip`) is opt-in for operators who accept that risk.

## Secrets

If `ip_hash_secret` is empty, hashing material is derived from `challenge.secret`. In production:

1. Set a strong `RG_CHALLENGE_SECRET`
2. Optionally set `RG_PRIVACY_IP_HASH_SECRET` to rotate hashes independently of challenge cookies

Rotating either secret invalidates derived identities and clearance cookies that depended on them.

## Log IP modes

| Mode | Behavior |
|------|----------|
| `off` | Do not log client IP material |
| `hash` | Log the privacy hash (default) |
| `full` | Log the resolved client IP |

Use `hash` or `off` unless debugging requires raw addresses.

## Challenge page notice

```toml
[privacy]
privacy_notice_url = "https://example.com/privacy"
```

When set, the challenge page includes a link to that URL.

## Env vars

- `RG_PRIVACY_HASH_CLIENT_IP`
- `RG_PRIVACY_IP_HASH_SECRET`
- `RG_PRIVACY_LOG_IP`
- `RG_PRIVACY_NOTICE_URL`
