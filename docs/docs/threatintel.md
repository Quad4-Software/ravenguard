---
title: Threat intel
description: Fleet ledger export, STIX and CSV ingest, AbuseIPDB and MISP sync.
---

# Threat intel

Open threat intel sits on the hub (or combined all mode). It exports the fleet threat ledger, ingests STIX or CSV feeds, and can sync AbuseIPDB or MISP. New indicators land in the same ledger that fans out bans and overlays to online proxies.

File blocklists and Q-Feeds still deny on the edge. Threat intel is the shared ledger path for operators and external feeds. See [Blocklists and feeds](./blocklists.md) for local lists.

## Privacy defaults

Exports omit raw IPs unless you turn on export_raw_ip. Bind hashes, User-Agent needles, domains, and JA4 values still export. AbuseIPDB reports that send a raw IP require export_raw_ip or an explicit confirm_raw on the report call.

Keep privacy bind secrets aligned across the fleet so shared bind keys match. See [Privacy](./privacy.md).

## Config

```toml
[threatintel]
enabled = true
export_raw_ip = false
# export_token = ""           # bearer for STIX/CSV pollers without a session
# abuseipdb_key = ""
abuseipdb_min_confidence = 80
abuseipdb_limit = 10000
# misp_url = ""
# misp_key = ""
# ingest_urls = ["https://example.com/feed.csv"]
ingest_interval = "1h"
default_ttl = "24h"
```

| Setting | Meaning |
|---------|---------|
| enabled | Hub poller for ingest_urls runs when true |
| export_raw_ip | Include raw IPv4/IPv6 in STIX and CSV exports |
| export_token | Optional bearer (or X-RG-Export-Token) for export URLs |
| abuseipdb_* | Blacklist pull and optional report API |
| misp_* | Attribute pull from a MISP instance |
| ingest_urls | HTTPS feed URLs polled on ingest_interval |
| default_ttl | TTL used when an IOC omits ttl_seconds (capped at 7 days on ingest) |

Secrets belong in the TOML on the hub or via live PUT /threatintel/config. Keys are redacted on GET (only *_set flags are shown).

## Admin UI

The **Threat intel** page covers:

- Download STIX or CSV of the current ledger
- Toggle export_raw_ip
- Paste CSV or STIX bodies, or pull a feed URL
- Sync AbuseIPDB blacklist and MISP attributes when keys are configured
- Report a single IP to AbuseIPDB (with raw-IP confirmation)

Ingested rows fan out to online proxies the same way operator bans do.

## API

Base path: `{base_path}/api/v1`

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | /threatintel/export.stix | session, API token, or export_token | STIX 2.1 bundle |
| GET | /threatintel/export.csv | session, API token, or export_token | CSV attachment |
| POST | /threatintel/ingest?format= | admin write + CSRF | Body is CSV or STIX |
| POST | /threatintel/ingest/url | admin write + CSRF | JSON url and optional format |
| POST | /threatintel/abuseipdb/sync | admin write + CSRF | Pull blacklist |
| POST | /threatintel/abuseipdb/report | admin write + CSRF | Report one IP |
| POST | /threatintel/misp/sync | admin write + CSRF | Pull recent attributes |
| GET/PUT | /threatintel/config | viewer read / admin write | Settings + last sync status |

Fleet ledger CRUD remains on GET/POST /threat (Bans page). Threat intel is the interchange and feed layer on top of that ledger.

## Formats

CSV columns: type, value, ttl_seconds, reason, source, confidence. Header optional when the first column is a known type.

Supported types: ipv4, ipv6, ip, domain, dns, hostname, ua, user-agent, ja4, bind.

STIX export uses indicator objects. Ingest accepts STIX 2.x bundles with IP, domain, and URL observables mapped to ledger keys.

## Pipeline effect

On each proxy, applied ledger entries become protect temp bans (bind or IP) or overlay denials for UA, JA4, DNS, and IP. Overlay checks run with the blocklist stage. Details: [Architecture](./architecture.md).
