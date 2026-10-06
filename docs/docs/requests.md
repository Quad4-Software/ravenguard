---
title: Requests
description: Look up WAF deny events by request ID.
---

# Requests

Every blocked, challenged, rate-limited, Coraza, OpenAPI, or access-denied outcome stores a structured event keyed by the response request ID (X-RavenGuard-Request-ID by default, or the configured stealth request_id_header).

Use the admin **Requests** page to paste a request ID from a block or challenge page and see method, path, host, User-Agent, hashed IP, score, and detail fields. Labeled ML shadow samples for adaptation also start from this page.

Events are kept in memory and in SQLite (waf_events) when the admin store is available. Retention defaults to privacy.waf_events_ttl (24h). In fleet mode, select a proxy to query that edge via the agent RPC.
