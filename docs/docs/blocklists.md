---
title: Blocklists and feeds
description: IP, hostname, and User-Agent deny lists, allowlists, plus optional Q-Feeds.
---

# Blocklists and feeds

Blocklists deny clients before rate limits and detection run. Allowlists skip detect and challenge for trusted clients.

## File-based blocklists

```toml
[blocklists]
ip_files = ["/etc/ravenguard/blocklists/ips.txt"]
dns_files = ["/etc/ravenguard/blocklists/domains.txt"]
ua_files = ["/etc/ravenguard/blocklists/ua.txt"]
reload_interval = "30s"
```

Lists reload on `reload_interval` without restarting. Update files in place on durable storage.

### IP lists

One IPv4/IPv6 address or CIDR per line. Blank lines and `#` comments are ignored.

```text
# scanners
203.0.113.0/24
2001:db8::/32
```

### Hostname lists

One hostname or domain suffix per line. Matching is lowercase with trailing dots stripped.

```text
evil.example
.bad-cdn.example
```

### User-Agent lists

Substring match against the request User-Agent.

```text
SomeBadBot
Bytespider
```

Sample files: [`testdata/blocklists/`](https://github.com/Quad4-Software/ravenguard/tree/main/testdata/blocklists).

## File-based allowlists

Allowlists skip detect scoring and challenge for matching clients. Protect, blocklists, Q-Feeds, rate limits, attack signatures, and access policies still apply.

```toml
[allowlists]
ip_files = ["/etc/ravenguard/allowlists/ips.txt"]
ua_files = ["/etc/ravenguard/allowlists/ua.txt"]
header_files = ["/etc/ravenguard/allowlists/headers.txt"]
reload_interval = "30s"
```

Any single match is enough (IP **or** User-Agent substring **or** header). Empty lists have no effect.

### Header lists

One `Header-Name: value` pair per line. The header name is matched case-insensitively. The value must match exactly.

```text
X-RG-Allow: trusted
X-Internal-Token: replace-me
```

Sample files: [`testdata/allowlists/`](https://github.com/Quad4-Software/ravenguard/tree/main/testdata/allowlists).

## Q-Feeds

Optional threat-intel feeds merge into the same deny path:

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
| `refresh` | In-memory cache refresh interval |
| `on_error` | `fail_open` continues serving if refresh fails. `fail_closed` denies on feed errors |
| `limit` | Optional cap on cached entries |

Env: `RG_QFEEDS_ENABLED`, `RG_QFEEDS_API_TOKEN`, or `QFEEDS_API_TOKEN`.

## Notes

- Use UA and IP lists for known abusive sources
- Use detect scoring for ambiguous traffic rather than large UA deny lists
- Use allowlists for health checks, office CIDRs, or shared header tokens that should skip detect and challenge
- Search-bot User-Agents are not DNS-verified. Do not blanket-block known crawler names unless that is intentional. Prefer allowlists only for sources you control
- Choose `reload_interval` for ops response time without excessive disk reads
