---
title: Detection
description: Heuristic scoring, behavior windows, and proxy bot signals.
---

# Detection

The detect stage scores HTTP clients. Scores at or above the configured thresholds challenge or block before the origin.

## Score thresholds

```toml
[detect]
enabled = true
challenge_score = 40
block_score = 90
```

- At `challenge_score`, send the browser challenge (when challenge is enabled)
- At `block_score`, or after repeated challenge strikes, hard-block

## HTTP heuristics

| Signal | Config key | Default |
|--------|------------|---------|
| Missing User-Agent | `missing_ua_score` | Empty UA |
| Scanner UA | `scanner_ua_score` | Known scanner / tool strings |
| AI crawler UA | `ai_ua_score` | Common AI fetch agents |
| Probe paths | `probe_path_score` | Exploit and recon URLs |
| Odd methods | `odd_method_score` | Unusual HTTP methods |
| Missing Accept | `missing_accept_score` | Incomplete browser headers |
| Missing Accept-Language | `missing_accept_lang_score` | Incomplete browser headers |
| Missing Sec-Fetch | `missing_sec_fetch_score` | Missing modern browser hints |
| Sec-CH-UA mismatch | `sec_ch_ua_mismatch_score` | Client hints disagree |
| `*/*` Accept as browser | `star_accept_browser_score` | Overly generic Accept |
| Empty form context | `empty_form_context_score` | Browser-like POST/PUT/PATCH missing Origin and Referer |
| Forum write path | `forum_write_path_score` | Suspicious POSTs to comment/register/reply style paths |

Raise `challenge_score` to challenge less often. Lower it to challenge earlier.

## Behavior windows

```toml
[detect]
behavior_window = "1m"
behavior_burst_limit = 60
behavior_burst_score = 35
behavior_path_fanout = 40
behavior_path_fanout_score = 30
behavior_strike_limit = 3
behavior_strike_score = 25
behavior_write_burst_limit = 20
behavior_write_burst_score = 35
behavior_write_repeat_limit = 8
behavior_write_repeat_score = 40
empty_form_context_score = 30
forum_write_path_score = 25
```

- **Burst** adds score when a client exceeds `behavior_burst_limit` in the window
- **Path fan-out** scores clients that hit many distinct paths quickly
- **Write burst** scores rapid POST/PUT/PATCH volume (default 20/min) without treating normal API traffic as a hard block by itself
- **Write repeat** only escalates repeated posts to spam-prone path segments such as `comment` / `register` / `reply`
- **Strikes** escalate clients that keep failing challenges

Empty form context applies to browser-like clients posting `application/x-www-form-urlencoded` or `multipart/form-data` (or spam-prone path segments) without Origin and Referer. Ordinary JSON API writes are not scored by that signal.

Privacy hashing applies when enabled. `privacy.retention` bounds how long this state is kept.

## High 404 policy

```toml
[detect]
high_404_threshold = 20
high_404_window = "1m"
high_404_action = "challenge"   # or "block" / "off"
```

Clients that produce many origin 404s in the window can be challenged or blocked.

## Proxy bot signals

```toml
[detect.proxy_signals]
bot_score_header = "CF-Bot-Score"
bot_score_header_2 = "X-Bot-Score"
ja4_header = "X-JA4"
low_score_points = 40
```

TLS fingerprints are not reconstructed after the reverse proxy. Forward edge headers such as `X-JA4` or Cloudflare bot scores to reuse them.

## Combined with protect

Protect handles size caps, concurrency, exploit probes, and temp bans. Detection handles likelihood scoring. Both stages run independently.

## Limits

- Obvious scanners and scrapers are scored and challenged or blocked
- Built-in AI UA scoring covers major training crawlers, answer-engine indexers, and user-triggered fetch agents (OpenAI, Anthropic, Perplexity, Google AI, Meta, Apple Intelligence token, and others)
- Sample `ua_files` hard-block AI agents and common scraper libraries while leaving search crawlers such as Googlebot and Applebot alone
- Automation that fails the challenge env probe (webdriver, Playwright, Puppeteer, Selenium, headless) is denied clearance
- Browser-like agents that spoof headers and solve PoW can still pass
- Verified search-bot allowlisting is not implemented. Do not treat User-Agent strings alone as proof of legitimacy. Use `[allowlists]` only for sources you control (office CIDRs, health-check UAs, shared header tokens)
