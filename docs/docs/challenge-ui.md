---
title: Challenge and UI
description: Browser proof-of-work, clearance cookies, and interstitial pages.
---

# Challenge and UI

RavenGuard can present a dark interstitial page that runs a JavaScript proof-of-work puzzle and a compact browser environment probe before issuing a clearance cookie.

## Modes

| Mode | Behavior |
|------|----------|
| `detect` | Challenge when heuristics, rate-limit policy, or high-404 policy say so |
| `always` | Challenge every request that lacks a valid clearance cookie |

```toml
[challenge]
enabled = true
mode = "detect"
difficulty = 16
cookie_name = "rg_clear"
cookie_ttl = "24h"
secret = "rg-dev-secret-replace-me!!"
path_prefix = "/_rg"
```

Override the secret in production with `RG_CHALLENGE_SECRET` (minimum 16 characters, not `change-me*`).

## Clearance cookie

- Name defaults to `rg_clear`
- HMAC-signed to the privacy client key (hashed IP by default)
- TTL from `cookie_ttl`
- Challenge tokens are bound to that key and are single-use

When TLS terminates upstream, `trust.proto_header` (default `X-Forwarded-Proto`) sets the cookie Secure flag.

## Environment probe

The challenge page also sends a compact environment report covering:

- `navigator.webdriver` and related automation markers
- Playwright / automation fingerprints the page can observe
- Interaction and solve timing signals

Automation-positive reports are refused clearance. Sophisticated spoofing can still lie in JavaScript. Treat the challenge as friction, not a cryptographic guarantee.

## Optional captcha hook

```toml
[challenge.captcha]
enabled = false
# provider = "stub"
# token = "ok"
```

Env: `RG_CAPTCHA_ENABLED`, `RG_CAPTCHA_PROVIDER`, `RG_CAPTCHA_TOKEN`.

## Branding and copy

```toml
[ui]
brand = "RavenGuard"
status_text = "Checking your browser before accessing this site."
test_mode = false
```

`privacy.privacy_notice_url` adds a privacy notice link on the challenge page when set.

## Test mode

```toml
[ui]
test_mode = true
```

Or `-test-mode` / `RG_UI_TEST_MODE=true`. Leave off in production.

Open `/_rg/test` for links to challenge, block, rate-limit, upstream, and error page previews.

## SEO and meta

Configured under `[site]`:

| Key | Purpose |
|-----|---------|
| `public_url` | Canonical and Open Graph base |
| `description` | Meta description |
| `og_image` | Social image (defaults relative to public URL + raven asset) |
| `theme_color` | Browser theme color (`#050505` by default) |
| `robots` | Robots meta |
| `lang` | HTML lang |

Served assets:

- `/robots.txt`
- `/site.webmanifest`
- `/_rg/static/favicon.ico` and PNG icons
- `/_rg/static/raven.png`

Default robots meta is `noindex, nofollow` because these pages are guard interstitials, not marketing content.
