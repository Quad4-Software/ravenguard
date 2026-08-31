---
title: Detection
description: Heuristic scoring, behavior windows, and proxy bot signals.
---

# Detection

The detect stage scores suspicious HTTP clients and either challenges or blocks them before the origin sees the request.

## Score thresholds

```toml
[detect]
enabled = true
challenge_score = 40
block_score = 90
```

- Reach `challenge_score` to send the browser challenge (when challenge is enabled)
- Reach `block_score`, or accumulate repeated challenge strikes, to hard-block

## HTTP heuristics

Points can be added for:

| Signal | Config key | Default idea |
|--------|------------|--------------|
| Missing User-Agent | `missing_ua_score` | Empty UA looks non-browser |
| Scanner UA | `scanner_ua_score` | Known scanner / tool strings |
| AI crawler UA | `ai_ua_score` | Common AI fetch agents |
| Probe paths | `probe_path_score` | Exploit and recon URLs |
| Odd methods | `odd_method_score` | Unusual verbs for a site |
| Missing Accept | `missing_accept_score` | Incomplete browser profile |
| Missing Accept-Language | `missing_accept_lang_score` | Incomplete browser profile |
| Missing Sec-Fetch | `missing_sec_fetch_score` | Missing modern browser hints |
| Sec-CH-UA mismatch | `sec_ch_ua_mismatch_score` | Client hints disagree |
| `*/*` Accept as browser | `star_accept_browser_score` | Overly generic Accept |

Tune scores to your traffic. Raising `challenge_score` reduces friction. Lowering it challenges earlier.

## Behavior windows

Short-window trackers catch soft abuse that single-request heuristics miss:

```toml
[detect]
behavior_window = "1m"
behavior_burst_limit = 60
behavior_burst_score = 35
behavior_path_fanout = 40
behavior_path_fanout_score = 30
behavior_strike_limit = 3
behavior_strike_score = 25
```

- **Burst** adds score when a client exceeds `behavior_burst_limit` in the window
- **Path fan-out** scores clients that hit many distinct paths quickly
- **Strikes** escalate clients that keep tripping soft signals

Privacy hashing applies to these trackers when enabled, and `privacy.retention` bounds how long soft state is kept.

## High 404 policy

```toml
[detect]
high_404_threshold = 20
high_404_window = "1m"
high_404_action = "challenge"   # or "block" / "off"
```

Clients that generate many origin 404s in a short window can be challenged or blocked. Useful against content scrapers and blind path scanners.

## Proxy bot signals

If your edge already computes bot reputation, forward it:

```toml
[detect.proxy_signals]
bot_score_header = "CF-Bot-Score"
bot_score_header_2 = "X-Bot-Score"
ja4_header = "X-JA4"
low_score_points = 40
```

TLS fingerprints are not reconstructed after the reverse proxy. Headers like `X-JA4` or Cloudflare bot scores are the practical way to reuse edge signals.

## Combined with protect

Protect still handles size caps, concurrency, exploit probes, and temp bans independently. Detection is about likelihood scoring. Protect is about hard resource and attack constraints. Use both.

## Realistic expectations

- Obvious scanners and scrapers are caught cheaply
- Automation that fails the challenge env probe is blocked at the gate
- Fully browser-like agents that solve PoW can still pass
- Keep allowlisting of verified search bots as a future ops concern. Do not assume UA strings alone prove legitimacy
