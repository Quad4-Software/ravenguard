# Agent notes for RavenGuard

## Admin UI (HTMX 4, Go templates)

The admin console is a dependency-free, server-rendered Go + HTMX 4 UI:

- Entry: `internal/admin/ui/ui.go`
- Routes/handlers: `internal/admin/ui/routes.go`
- Helpers/template funcs: `internal/admin/ui/helpers.go`
- Templates: `internal/admin/ui/templates/*.html` and `templates/pages/*.html`
- Vendored assets: `internal/admin/ui/assets/` (HTMX 4, IBM Plex fonts, raven.png, favicon.ico)
- Static assets and templates are embedded with `//go:embed assets/* templates/*`

The UI dispatches to the existing JSON admin API via `httptest.NewRecorder`.
It uses the same session cookie and CSRF mechanism as the previous Svelte UI.

## Build and test (no pnpm for admin)

- Build: `go build ./...` or `make build`
- Test: `go test ./...` or `make test`
- Format: `gofmt -w -s .`
- Vet: `go vet ./...`

The `make admin` target is a no-op now. `make widget` is also a no-op because the widget runtime files are vendored under `internal/ui/static/`.

## Running the admin UI locally

```
go run ./cmd/ravenguard -admin-enabled -admin-listen 127.0.0.1:9090 -admin-data-dir .tmp/admin-data -log-level warn -config configs/ravenguard.toml -listen-http :18080
```

The initial owner password is printed to the log and `admin-data-dir/initial_admin_password` on first start.
