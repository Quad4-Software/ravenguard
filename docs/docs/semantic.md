# Semantic analysis

RavenGuard can inspect request path, query, and body with bounded decode and intent scoring for SQLi, XSS, command injection, and path traversal.

## Config

```toml
[semantic]
enabled = false
mode = "shadow"
max_body_inspect = 65536
max_decode_depth = 3
max_decode_bytes = 262144
max_cpu_ns = 2000000
strict_budget = false
families = ["sqli", "xss", "cmd", "path"]
skip_path_prefixes = ["/_rg"]
```

Modes:

- **shadow** log only (default)
- **challenge** raise challenge when score is high
- **block** hard block on high-confidence matches

CPU and decode budgets abort analysis to avoid decode bombs. In shadow mode budget aborts fail open.

## Pipeline

Semantic runs after Coraza and builtin attack signatures, before detect score merge. Body capture is shared via bodybuf when needed.
