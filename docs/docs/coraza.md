---
title: Coraza
description: Optional Coraza / OWASP CRS request inspection engine.
---

# Coraza

RavenGuard can embed [OWASP Coraza](https://coraza.io) with the OWASP Core Rule Set as an optional request inspection engine.

```toml
[coraza]
enabled = false
mode = "block"          # block | detect
crs = true
paranoia = 1
max_body_inspect = 1048576
skip_path_prefixes = ["/_rg"]
```

When `crs = true`, the embedded CRS is loaded. You can also set `rules_dir`, `rules_file`, or inline `directives`.

In `block` mode, Coraza interruptions deny the request and the builtin path/query attack signatures are skipped. In `detect` mode, matches are logged as Ray events without blocking, and builtin attack signatures still run.

Live admin toggles cover `enabled`, `mode`, and `paranoia`. Changing CRS / rules paths requires a process restart so the WAF can reload.
