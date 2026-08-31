---
title: Privacy
description: Client IP hashing, log redaction, and retention controls.
---

# Privacy

RavenGuard defaults to privacy-friendly client identity handling. These are engineering controls, not a legal certification.

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

- Rate limits, 404 tracking, behavior windows, and clearance binding use a pseudonymous key
- Logs prefer a hash instead of the raw address when `log_ip = "hash"`
- Soft in-memory state is bounded by `retention`

## Secrets

If `ip_hash_secret` is empty, RavenGuard derives hashing material from `challenge.secret`. In production:

1. Set a strong `RG_CHALLENGE_SECRET`
2. Optionally set a dedicated `RG_PRIVACY_IP_HASH_SECRET` if you want hash rotation independent of challenge cookies

Rotating either secret invalidates derived identities and existing clearance cookies that depended on them.

## Log IP modes

| Mode | Behavior |
|------|----------|
| `off` | Do not log client IP material |
| `hash` | Log the privacy hash (default) |
| `full` | Log the resolved client IP |

Prefer `hash` or `off` unless debugging requires raw addresses.

## Challenge page notice

Set `privacy_notice_url` to surface a link on the challenge interstitial:

```toml
[privacy]
privacy_notice_url = "https://example.com/privacy"
```

## Env vars

- `RG_PRIVACY_HASH_CLIENT_IP`
- `RG_PRIVACY_IP_HASH_SECRET`
- `RG_PRIVACY_LOG_IP`
- `RG_PRIVACY_NOTICE_URL`
