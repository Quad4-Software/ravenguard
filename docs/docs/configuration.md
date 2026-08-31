---
title: Configuration
description: TOML, environment variables, and CLI flags.
---

# Configuration

Precedence (highest wins):

1. CLI flags
2. Environment variables (`RG_*`)
3. TOML file (`-config` / `RG_CONFIG`)
4. Built-in defaults

Full example: [`configs/ravenguard.toml`](https://github.com/Quad4-Software/ravenguard/blob/main/configs/ravenguard.toml).

## Common flags

| Flag | Env | Meaning |
|------|-----|---------|
| `-config` | `RG_CONFIG` | TOML path |
| `-listen-http` | `RG_LISTEN_HTTP` | HTTP bind |
| `-listen-https` | `RG_LISTEN_HTTPS` | HTTPS bind |
| `-listen-quic` | `RG_LISTEN_QUIC` | HTTP/3 bind |
| `-upstream` | `RG_UPSTREAM_URL` | Origin URL (`http://`, `https://`, `ws://`, `wss://`, `unix://`) |
| `-challenge-secret` | `RG_CHALLENGE_SECRET` | HMAC secret (min 16 chars, not `change-me*`) |
| `-public-url` | `RG_SITE_PUBLIC_URL` | Canonical / Open Graph base URL |
| `-test-mode` | `RG_UI_TEST_MODE` | Enable `/_rg/test` UI previews |
| `-log-level` | `RG_LOG_LEVEL` | `debug` / `info` / `warn` / `error` |
| `-log-format` | `RG_LOG_FORMAT` | `text` / `json` |

## Listen and TLS

```toml
[listen]
http = ":8080"
# https = ":8443"
# quic = ":8443"

[tls]
# cert_file = "/certs/fullchain.pem"
# key_file = "/certs/privkey.pem"
```

Typical layout: RavenGuard on plain HTTP behind the reverse proxy, TLS at the edge.

## Upstream

```toml
[upstream]
url = "http://127.0.0.1:8000"
# url = "https://127.0.0.1:8443"
# url = "ws://127.0.0.1:8000"    # alias for http://
# url = "wss://127.0.0.1:8443"   # alias for https://
# url = "unix:///var/run/app.sock"
connect_timeout = "5s"
response_header_timeout = "30s"
idle_conn_timeout = "90s"
max_idle_conns = 256
# set_headers = ["X-RavenGuard: 1"]

[upstream.health]
enabled = false
path = "/healthz"
interval = "10s"
timeout = "3s"
```

`ws://` and `wss://` are scheme aliases for the same TCP origin as `http://` and `https://`. WebSocket traffic is an HTTP upgrade on that connection. When `[challenge]` is enabled, upgrades require an existing clearance cookie from a prior page load (browsers cannot run the JS puzzle during a handshake). Forward WebSocket upgrades from your reverse proxy to RavenGuard.

Env: `RG_UPSTREAM_URL`, `RG_UPSTREAM_HEALTH_ENABLED`, `RG_UPSTREAM_HEALTH_PATH`.

## Trust

```toml
[trust]
mode = "behind_proxy"   # or "edge"
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
real_ip_header = "X-Real-IP"
proto_header = "X-Forwarded-Proto"
proxy_protocol = false
```

`behind_proxy` refuses to start without `trusted_proxies`.

Env: `RG_TRUST_MODE`, `RG_REAL_IP_HEADER`, `RG_PROTO_HEADER`, `RG_PROXY_PROTOCOL`.

## Blocklists and Q-Feeds

```toml
[blocklists]
ip_files = ["testdata/blocklists/ips.txt"]
dns_files = ["testdata/blocklists/domains.txt"]
ua_files = ["testdata/blocklists/ua.txt"]
reload_interval = "30s"

[qfeeds]
enabled = false
# api_token = ""  # or QFEEDS_API_TOKEN / RG_QFEEDS_API_TOKEN
base_url = "https://api.qfeeds.com"
feeds = ["malware_ip", "malware_domains"]
refresh = "1h"
on_error = "fail_open"
```

Details: [Blocklists and feeds](./blocklists.md).

## Rate limit

```toml
[ratelimit]
enabled = true
requests = 120
window = "1m"
burst = 60
per_path = false
challenge_over = true
```

When `challenge_over` is true, over-limit clients may receive a challenge instead of an immediate reject, depending on challenge settings.

## Protect

```toml
[protect]
enabled = true
max_body_bytes = 1048576
max_header_bytes = 16384
max_url_bytes = 8192
max_concurrent_global = 2048
max_concurrent_per_client = 16
ban_after_strikes = 5
ban_ttl = "10m"
attack_block = true
attack_score = 90
write_method_cost = 3
```

Blocks common path and query exploit probes. Caps body, URL, and header size. Limits concurrency. Charges POST/PUT/PATCH/DELETE more against the rate limiter. Temp-bans clients after repeated strikes.

## Detect

HTTP scoring adds points for scanner and AI User-Agents, missing browser headers, probe paths, behavior bursts, path fan-out, and optional proxy bot-score headers. Scores at `challenge_score` trigger the JS challenge. `block_score` or repeated challenge strikes hard-block.

```toml
[detect]
enabled = true
challenge_score = 40
block_score = 90
ai_ua_score = 55
missing_accept_lang_score = 15
missing_sec_fetch_score = 20
behavior_burst_limit = 60
behavior_strike_limit = 3

[detect.proxy_signals]
bot_score_header = "CF-Bot-Score"
bot_score_header_2 = "X-Bot-Score"
ja4_header = "X-JA4"
low_score_points = 40
```

Full knobs: [Detection](./detection.md).

## Challenge, UI, and site

```toml
[challenge]
enabled = true
mode = "detect"          # or "always"
difficulty = 16
cookie_name = "rg_clear"
cookie_ttl = "24h"
secret = "rg-dev-secret-replace-me!!"
path_prefix = "/_rg"

[challenge.captcha]
enabled = false

[ui]
brand = "RavenGuard"
status_text = "Checking your browser before accessing this site."
test_mode = false

[site]
# public_url = "https://example.com"
description = "RavenGuard application guard"
theme_color = "#050505"
robots = "noindex, nofollow"
lang = "en"
```

Env: `RG_CHALLENGE_ENABLED`, `RG_CHALLENGE_MODE`, `RG_CHALLENGE_DIFFICULTY`, `RG_CHALLENGE_PATH_PREFIX`, `RG_CAPTCHA_ENABLED`, `RG_CAPTCHA_PROVIDER`, `RG_CAPTCHA_TOKEN`, `RG_UI_BRAND`, `RG_UI_STATUS_TEXT`, `RG_SITE_DESCRIPTION`, `RG_SITE_OG_IMAGE`, `RG_SITE_THEME_COLOR`, `RG_SITE_ROBOTS`, `RG_SITE_LANG`.

## Privacy and logging

```toml
[privacy]
hash_client_ip = true
# ip_hash_secret = ""   # empty derives from challenge.secret
log_ip = "hash"         # off | hash | full
retention = "30m"
# privacy_notice_url = "https://example.com/privacy"

[logging]
level = "info"
format = "text"
```

See [Privacy](./privacy.md).

## Other env vars

- `RG_TLS_CERT_FILE`, `RG_TLS_KEY_FILE`
- `RG_QFEEDS_ENABLED`, `RG_QFEEDS_API_TOKEN` (or `QFEEDS_API_TOKEN`)
- `RG_PRIVACY_HASH_CLIENT_IP`, `RG_PRIVACY_IP_HASH_SECRET`, `RG_PRIVACY_LOG_IP`, `RG_PRIVACY_NOTICE_URL`

## Sandbox (Landlock + seccomp-bpf)

Linux-only. Default is `best_effort` so older kernels keep running.

```toml
[sandbox]
mode = "best_effort"   # off | try | best_effort | enforce

[sandbox.landlock]
# mode = ""            # inherit sandbox.mode when empty
restrict_net = true
restrict_scoped = true
ignore_missing = true
# ro_dirs / rw_dirs / ro_files / rw_files for extra paths
# bind_tcp / connect_tcp are derived from listen + upstream when empty

[sandbox.seccomp]
# mode = ""
deny_action = "errno"  # errno | kill_thread | kill_process | trap | log
```

| Mode | Behavior |
|------|----------|
| `off` | Disabled |
| `try` | Apply with graceful ABI degrade. Failure is logged and ignored |
| `best_effort` | Soft-fail. Landlock uses `BestEffort()` so missing LSM still succeeds |
| `enforce` | Hard-fail startup if Landlock ABI or seccomp cannot be applied |

Env: `RG_SANDBOX_MODE`, `RG_SANDBOX_LANDLOCK_MODE`, `RG_SANDBOX_SECCOMP_MODE`, `RG_SANDBOX_SECCOMP_DENY_ACTION`, `RG_SANDBOX_LANDLOCK_RESTRICT_NET`, `RG_SANDBOX_LANDLOCK_RESTRICT_SCOPED`, `RG_SANDBOX_LANDLOCK_IGNORE_MISSING`.

When Landlock network rules are enabled, listeners use classic TCP (not Multipath TCP) so bind/connect rules apply.
