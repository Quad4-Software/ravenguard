# Admin control plane

RavenGuard can run a separate management listener with multi-user auth, an embedded SPA, and a JSON API. The admin surface is never mounted on the public WAF pipeline.

## Enable

```toml
[admin]
enabled = true
listen = "127.0.0.1:9090"
base_path = "/"
data_dir = "./data/admin"
bootstrap_user = "admin"
session_ttl = "12h"
cookie_secure = "auto"
```

On first start with an empty database, RavenGuard creates one `owner`. If `bootstrap_password` / `RG_ADMIN_BOOTSTRAP_PASSWORD` is unset, a random password is generated, printed once in the process log, and written to `data_dir/initial_admin_password` (mode `0600`). That file is removed after the first successful login. Later starts do not recreate users.

You can still set an explicit bootstrap password instead of auto-generation.

Environment overrides:

- `RG_ADMIN_ENABLED`
- `RG_ADMIN_LISTEN`
- `RG_ADMIN_DATA_DIR`
- `RG_ADMIN_BOOTSTRAP_USER`
- `RG_ADMIN_BOOTSTRAP_PASSWORD`
- `RG_ADMIN_BASE_PATH`
- `RG_ADMIN_COOKIE_SECURE`
- `RG_ADMIN_SESSION_TTL`

CLI:

- `-admin-enabled`
- `-admin-listen`
- `-admin-data-dir`

Default listen is loopback (`127.0.0.1:9090`). Do not expose the admin port to the public internet without TLS, an allowlist, VPN, or mTLS.

## Roles

| Role | Capabilities |
|------|----------------|
| `viewer` | Read status, bans, blocklists, config, audit |
| `admin` | Viewer plus ban management, blocklist reload, live config edits, user management (except owners), own API tokens |
| `owner` | Admin plus manage owners and revoke any token |

The last remaining owner cannot be deleted or demoted.

## Auth

- Passwords use argon2id
- Browser sessions use an HttpOnly `rg_admin_session` cookie and `X-CSRF-Token` on mutating requests
- Automation can use bearer API tokens (`rgat_<id>.<secret>`). Token secrets are shown once at creation and stored hashed

## API

Base path: `{base_path}/api/v1`

| Method | Path | Notes |
|--------|------|-------|
| POST | `/auth/login` | username + password |
| POST | `/auth/logout` | |
| GET | `/auth/me` | current user + csrf |
| POST | `/auth/password` | change own password |
| PATCH | `/auth/profile` | change own username |
| GET | `/status` | live overview |
| GET | `/status/history` | status time series |
| GET/POST/DELETE | `/bans` | list, create, unban (`?key=`) |
| GET | `/blocklists` | sizes + last reload |
| POST | `/blocklists/reload` | |
| GET/POST/DELETE | `/blocklists/entries` | entry management |
| GET/PUT | `/qfeeds` | live Q-Feeds settings (token redacted on GET) |
| POST | `/qfeeds/refresh` | force feed refresh |
| GET/PUT | `/config` | live safe subset + restart-required snapshot |
| POST | `/appearance/assets` | upload logo or favicon (`?kind=`) |
| GET | `/appearance/assets/{kind}` | serve uploaded asset |
| POST | `/appearance/preview` | HTML preview (`?page=`) |
| GET/POST | `/users` | |
| PATCH/DELETE | `/users/{id}` | |
| GET/POST | `/tokens` | |
| DELETE | `/tokens/{id}` | |
| GET | `/audit?cursor=&limit=` | |
| GET/POST | `/upstreams` | upstream inventory |
| GET/PATCH/DELETE | `/upstreams/{id}` | |
| GET/POST | `/routes` | host/path routing |
| GET/PATCH/DELETE | `/routes/{id}` | |
| GET/POST | `/access-policies` | password, PIN, header, CIDR, UA gates |
| GET/PATCH/DELETE | `/access-policies/{id}` | |
| GET | `/certs` | certificate inventory |
| POST | `/certs/manage` | ACME manage hosts |
| POST | `/certs/{host}/renew` | renew one host |
| GET/PUT/DELETE | `/certs/{host}` | detail, manual PEM upload, delete |
| GET | `/logs` | in-memory log ring |
| GET/POST | `/proxies` | list fleet proxies / enroll (returns one-time token) |
| PUT/DELETE | `/proxies/{id}` | update metadata or remove |
| POST | `/proxies/{id}/rotate-token` | new enrollment token |
| POST | `/proxies/{id}/push` | push desired config to online agent |
| GET | `/proxies/{id}/status` | live status from agent when online |
| GET/POST | `/migrations` | list / create Move services jobs |
| GET | `/migrations/{id}` | migration detail + DNS checklist |
| POST | `/migrations/{id}/prep` | prep destination (routes + certs) |
| POST | `/migrations/{id}/complete` | finish cutover after DNS |
| POST | `/migrations/{id}/abort` | abort in-progress migration |

Agent connect (no session cookie): `POST` upgrade WebSocket at `/api/v1/agent/connect` with mutual auth.

## Live vs restart-required config

`PUT /config` updates a safe subset that is applied immediately and persisted under `data_dir`:

- rate limit thresholds
- protect limits and ban settings
- detect scores and windows
- challenge mode / difficulty / cookie TTL / algorithm
- UI appearance (brand, status text, colors, fonts, page titles, custom CSS, site meta)
- trust mode, live trusted proxy CIDRs, real-IP and proto headers, PROXY protocol flag
- stealth fingerprint controls
- privacy and logging knobs
- Q-Feeds settings (merged into the same overrides blob so other live fields are not replaced)

Listen addresses, TLS mode/bind, TOML upstream URL, sandbox, secrets, challenge path prefix, and admin bind settings remain restart-required in the UI.

The SPA Appearance page edits branding and theme tokens, uploads logo/favicon assets, and previews challenge/block/rate-limit pages via `/appearance/preview`. Q-Feeds changes from the Feeds page or `PUT /qfeeds` share the persisted config-overrides payload with other live fields.

When admin starts with an empty route table, RavenGuard seeds a default upstream and catch-all route from `[upstream].url`.

## Hub and multi-proxy fleet

RavenGuard can run as separate processes:

| Command | Role |
|---------|------|
| `ravenguard hub` | Admin SPA, SQLite, agent WebSocket accept (no public WAF) |
| `ravenguard proxy` | Public WAF + outbound agent to the hub |
| `ravenguard` / `ravenguard all` | Combined single-process mode (backcompat) |

Preferred deploy keeps the hub on a private overlay (Tailscale, Netbird, or WireGuard). Bind `admin.listen` to the overlay IP only. Proxies set `agent.hub_url` to that address. Operators open the panel from a machine on the same mesh. Nothing management-facing needs a public A record.

### Hub config

```toml
[admin]
enabled = true
listen = "100.64.0.10:9090"
data_dir = "./data/admin"

[hub]
public_url = "http://100.64.0.10:9090"
```

The hub Ed25519 keypair is created under `admin.data_dir` (`hub_ed25519.key` / `.pub`). Agents verify the hub with `agent.hub_pubkey`.

### Proxy agent config

```toml
[listen]
http = ":8080"

[agent]
hub_url = "http://100.64.0.10:9090"
token = "rgpt_..."
hub_pubkey = "..."
data_dir = "./data/proxy"
```

Enroll a proxy in the Proxies UI to get a one-time token and copy-paste TOML. Agents dial WebSocket at `{hub_url}/api/v1/agent/connect` with mutual auth (token, hub signature over token hash, machine fingerprint). The challenge does not echo the enrollment token. Connect attempts are rate-limited per source IP. Fingerprints cannot be reused across proxies. Universal enrollment tokens require an owner role.

Ops against a registered proxy never fall back to the hub process: if the agent is offline, the API returns an error instead of mutating local state.

### Move services

Use **Move services** to reassign routes between proxies: prep destination (routes + certs), update DNS to the destination public IP shown in the checklist, then complete cutover.

Environment:

- `RG_HUB_PUBLIC_URL`
- `RG_AGENT_HUB_URL`
- `RG_AGENT_TOKEN`
- `RG_AGENT_HUB_PUBKEY`
- `RG_AGENT_NAME`
- `RG_AGENT_DATA_DIR`

## Reverse proxy

Serve the admin UI behind a private reverse proxy:

```nginx
location /ravenguard/ {
  proxy_pass http://127.0.0.1:9090/;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto $scheme;
}
```

Set `admin.base_path = "/ravenguard"` so the SPA and cookies align with the path prefix. Prefer TLS termination and an IP allowlist on the proxy.

## Sandbox

When Landlock is enabled, RavenGuard derives:

- TCP bind permission for `admin.listen` / `admin.https`
- read-write access to `admin.data_dir` for SQLite

## Building the UI

```bash
make admin
make build
```

`make admin` builds `packages/admin` and copies assets into `internal/admin/ui/dist` for `go:embed`.
