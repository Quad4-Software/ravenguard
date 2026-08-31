---
title: Blocklists and feeds
description: IP, hostname, and User-Agent lists plus optional Q-Feeds threat intel.
---

# Blocklists and feeds

RavenGuard can deny clients before rate limits and detection scoring run.

## File-based blocklists

```toml
[blocklists]
ip_files = ["/etc/ravenguard/blocklists/ips.txt"]
dns_files = ["/etc/ravenguard/blocklists/domains.txt"]
ua_files = ["/etc/ravenguard/blocklists/ua.txt"]
reload_interval = "30s"
```

Lists reload on `reload_interval` without restarting the process. Keep files on durable storage and update them in place.

### IP lists

One IPv4/IPv6 address or CIDR per line. Blank lines and `#` comments are ignored.

```text
# scanners
203.0.113.0/24
2001:db8::/32
```

### Hostname lists

One hostname or domain suffix per line. Matching is normalized (lowercase, trailing-dot stripped).

```text
evil.example
.bad-cdn.example
```

### User-Agent lists

Substring matches against the request User-Agent. Use this to hard-block known scrapers and unwanted AI crawlers.

```text
SomeBadBot
Bytespider
```

Sample files live under [`testdata/blocklists/`](https://github.com/Quad4-Software/ravenguard/tree/main/testdata/blocklists).

## Q-Feeds

Optional threat-intel feeds merge into the same denial path:

```toml
[qfeeds]
enabled = true
api_token = ""           # or QFEEDS_API_TOKEN / RG_QFEEDS_API_TOKEN
base_url = "https://api.qfeeds.com"
feeds = ["malware_ip", "malware_domains"]
refresh = "1h"
on_error = "fail_open"
# limit = 100000
```

| Setting | Meaning |
|---------|---------|
| `feeds` | Feed names to pull |
| `refresh` | How often to refresh the in-memory cache |
| `on_error` | `fail_open` keeps serving if a refresh fails. Prefer this unless you explicitly want outages on feed errors |
| `limit` | Optional cap on cached entries |

Env: `RG_QFEEDS_ENABLED`, `RG_QFEEDS_API_TOKEN`, or `QFEEDS_API_TOKEN`.

## Operational tips

- Start with UA and IP lists for known abusive sources
- Prefer challenge/detect scoring for ambiguous traffic instead of huge brittle UA deny lists
- Legitimate search bots are not DNS-verified yet. Avoid blanket blocking of well-known crawler names unless you intend to
- Keep reload intervals short enough for ops response, long enough to avoid disk thrash
