---
title: OpenAPI gate
description: Per-route OpenAPI request schema enforcement.
---

# OpenAPI gate

Attach an OpenAPI 3 document to a route to enforce a positive security model: unknown methods and paths are denied, and request bodies must match the schema.

Create schemas in the admin **API schemas** page, then select one on a route. Modes:

- **block** deny non-conforming requests
- **detect** record a Ray event and allow the request

Server URL matching is disabled so Host headers behind RavenGuard do not false-deny. Response validation is not included in this release.
