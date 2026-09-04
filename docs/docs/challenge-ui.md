---
title: Challenge and UI
description: Proof-of-work widget, clearance cookies, and interstitial pages.
---

# Challenge and UI

When enabled, RavenGuard serves an interstitial with the @quad4/ravenguard-widget proof-of-work widget, then issues a clearance cookie.

## Modes

| Mode | Behavior |
|------|----------|
| detect | Challenge when heuristics, rate-limit policy, or high-404 policy require it |
| always | Challenge every request that lacks a valid clearance cookie |
| attack | Under-attack: challenge every request with the visible interactive gate |

```toml
[challenge]
enabled = true
mode = "detect"
algorithm = "adaptive"
difficulty = 16
env_probe = "on"
cookie_name = "rg_clear"
cookie_ttl = "24h"
secret = "rg-dev-secret-replace-me!!"
path_prefix = "/_rg"
```

algorithm may be adaptive (default), sha256, pbkdf2, or argon2id. Adaptive raises effort from detect score bands: SHA-256 for low risk, PBKDF2 for elevated or high risk.

## Gates

| Gate | When | UX |
|------|------|-----|
| invisible | detect / always at low or elevated risk | Auto PoW on load, no checkbox |
| interactive | attack mode, high risk, or after a failed invisible attempt | Visible checkbox (and captcha when enabled) |

The signed challenge JSON includes gate so clients cannot self-downgrade interaction rules. Invisible solutions may omit checkbox interaction. Automation markers still refuse clearance when env_probe is on (default). Set env_probe to off only for automated browser harnesses.

Override the secret in production with RG_CHALLENGE_SECRET (minimum 16 characters, not a change-me placeholder). Cookie name overrides: challenge.cookie_name or RG_CHALLENGE_COOKIE_NAME. Env probe: RG_CHALLENGE_ENV_PROBE.

## Protocol endpoints

| Method | Path | Role |
|--------|------|------|
| GET | {path_prefix}/v1/challenge | Issue a signed protocol v1 challenge JSON |
| POST | {path_prefix}/v1/verify | Verify a base64url payload (same handler as gate POST) |
| POST | {path_prefix}/challenge | Verify payload and set the clearance cookie |

## Clearance cookie

- Name defaults to rg_clear
- HMAC-signed to the privacy client key (hashed IP by default)
- TTL from cookie_ttl
- Challenge tokens are bound to that key and are single-use

When TLS terminates upstream, trust.proto_header (default X-Forwarded-Proto) sets the cookie Secure flag.

## Gate page assets

The challenge interstitial loads short-named static assets under {path_prefix}/static/:

| Asset | Role |
|-------|------|
| w.js | Obfuscated widget IIFE (custom element) |
| c.js | Obfuscated challenge page bootstrap |
| c.css | Challenge page stylesheet |

The page defines a bootstrap object (default window.__g__) with prefix, ray, and captcha. c.js reads window.__g__ (with a window.__RG__ fallback). Override the global name with stealth.bootstrap_global.

The custom element defaults to rg-check (stealth.element_name). Theme tokens are injected as CSS variables:

- --bg, --fg, --accent, --theme
- --font-sans, --font-mono

Set them under [ui] (background, foreground, accent, fonts) and site.theme_color.

## Environment probe

The widget reports automation markers, interaction, and solve timing. Automation-positive reports are refused clearance.

## Optional captcha hook

```toml
[challenge.captcha]
enabled = false
# provider = "ravenguard"
# provider = "stub"
# token = "ok"
```

ravenguard verifies the same protocol payload used by the widget. stub is for tests.

Env: RG_CAPTCHA_ENABLED, RG_CAPTCHA_PROVIDER, RG_CAPTCHA_TOKEN.

## Embeddable widget

Package: @quad4/ravenguard-widget under packages/widget.

```bash
pnpm add @quad4/ravenguard-widget
```

```ts
import '@quad4/ravenguard-widget'
```

```html
<rg-check challenge="https://example.com/_rg/v1/challenge"></rg-check>
```

The default custom element is rg-check. Importing the package also registers ravenguard-widget as an alias. register(tag) can define additional tags.

```ts
import { register, RavenGuardWidget, RGCheck } from '@quad4/ravenguard-widget'

register('my-check')
```

RGCheck is an alias of the RavenGuardWidget class. The default hidden field name is rg (override with the name attribute or stealth.widget_input_name).

Theme via theme="light", theme="dark", theme="auto", or CSS variables on the host (--rg-bg, --rg-fg, --rg-accent, or page --bg, --fg, --accent).

Or load the IIFE build (RGCheck global):

```html
<script src="/path/to/w.js"></script>
```

The npm package also ships dist/ravenguard-widget.min.js (same obfuscated IIFE).

Build and sync into the gate UI:

```bash
make widget
```

## Stealth notes

```toml
[stealth]
# ray_header = ""            # omit ray response header
# element_name = "rg-check"
# bootstrap_global = "__g__"
# hide_brand_mark = true
# generic_copy = true
# serve_manifest = false
# serve_root_icons = false
# widget_input_name = "rg"
```

Empty ray_header omits the ray response header. generic_copy swaps branded titles for generic copy and uses Ref instead of Ray ID. hide_brand_mark removes the footer logo. Turning off serve_manifest / serve_root_icons drops those public fingerprint paths.

## Branding and copy

```toml
[ui]
brand = "RavenGuard"
status_text = "Checking your browser before accessing this site."
test_mode = false
# background = "#050505"
# foreground = "#e8e8e8"
# accent = "#c4c4c4"
# challenge_title = ""
# challenge_subtitle = ""
# footer_text = ""
# contact = ""  # email, phone, URL, or free text on block/denied pages
# custom_css = ""
```

ui.contact (or RG_UI_CONTACT) shows on block, rate-limit, upstream, and error pages. Email, phone, and http(s) / mailto: / tel: values become links. Other text is shown as-is.

privacy.privacy_notice_url adds a privacy notice link on the challenge page when set. Live appearance edits are also available from the admin Appearance page.

## Test mode

```toml
[ui]
test_mode = true
```

Or -test-mode / RG_UI_TEST_MODE=true. Leave off in production.

Open /_rg/test for links to challenge, block, rate-limit, upstream, and error page previews.
