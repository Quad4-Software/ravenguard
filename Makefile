GOTOOLCHAIN ?= go1.26.6
GO ?= GOTOOLCHAIN=$(GOTOOLCHAIN) go
GOBIN ?= $(shell $(GO) env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)

# Tool module versions (pin for reproducible installs).
GOLANGCI_LINT_VERSION ?= v2.13.2
GOSEC_VERSION ?= latest
STATICCHECK_VERSION ?= latest
REVIVE_VERSION ?= latest
GOVULNCHECK_VERSION ?= latest
GOIMPORTS_VERSION ?= latest

# Minimum total statement coverage for the cover gate (percent).
COVER_MIN ?= 50

.PHONY: all build test cover bench fuzz tools fmt fix vet lint sec vuln check tidy clean widget admin

all: check build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/ravenguard ./cmd/ravenguard

widget:
	pnpm widget:build
	cp packages/widget/dist/w.js internal/ui/static/w.js
	rm -rf internal/ui/static/workers
	if [ -d packages/widget/dist/workers ]; then \
		mkdir -p internal/ui/static/workers; \
		cp packages/widget/dist/workers/*.js internal/ui/static/workers/; \
	fi
	node packages/widget/scripts/obfuscate.mjs internal/ui/static/challenge.js internal/ui/static/c.js
	cp internal/ui/static/challenge.css internal/ui/static/c.css

admin:
	pnpm admin:build
	rm -rf internal/admin/ui/dist
	mkdir -p internal/admin/ui/dist
	cp -a packages/admin/build/. internal/admin/ui/dist/
	touch internal/admin/ui/dist/.gitkeep

test:
	$(GO) test ./...
	pnpm widget:test
	pnpm admin:test

cover:
	$(GO) test ./... -covermode=atomic -coverprofile=coverage.out -count=1
	@$(GO) tool cover -func=coverage.out | awk '/^total:/{print}'
	@total=$$($(GO) tool cover -func=coverage.out | awk '/^total:/{gsub(/%/,"",$$NF); print $$NF}'); \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { \
		if ((t+0) < (m+0)) { \
			printf "coverage %.1f%% is below minimum %s%%\n", t, m; \
			exit 1 \
		} \
		printf "coverage %.1f%% meets minimum %s%%\n", t, m \
	}'

bench:
	$(GO) test ./... -run='^$$' -bench=. -benchmem -count=1

fuzz:
	$(GO) test ./internal/iputil -fuzz=FuzzParseIP -fuzztime=20s
	$(GO) test ./internal/blocklist -fuzz=FuzzParseIPOrCIDR -fuzztime=20s
	$(GO) test ./internal/blocklist -fuzz=FuzzNormalizeHost -fuzztime=20s
	$(GO) test ./internal/challenge -fuzz=FuzzVerifyPoW -fuzztime=20s
	$(GO) test ./internal/detect -fuzz=FuzzIsScannerUA -fuzztime=20s
	$(GO) test ./internal/qfeeds -fuzz=FuzzParseFeed -fuzztime=20s

# Install lint, security, and formatting tools into GOPATH/bin.
tools:
	$(GO) install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(GO) install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	$(GO) install github.com/mgechev/revive@$(REVIVE_VERSION)
	$(GO) install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

fmt:
	gofmt -w -s .
	goimports -w -local github.com/Quad4-Software/ravenguard .

# Apply Go API rewrites (go fix) across the module.
fix:
	$(GO) fix ./...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./cmd/... ./internal/...

# Standalone gosec pass (also covered by golangci-lint).
# Excludes match .golangci.yml gosec settings.
sec:
	gosec -quiet -exclude=G304,G118,G124 ./cmd/... ./internal/...

vuln:
	govulncheck ./cmd/... ./internal/...

# Full local quality gate: format check, fix, vet, lint, security, vulns, cover.
check:
	$(MAKE) fmt
	$(MAKE) fix
	$(MAKE) vet
	$(MAKE) lint
	$(MAKE) sec
	$(MAKE) vuln
	$(MAKE) cover

tidy:
	$(GO) mod tidy

clean:
	rm -rf bin/ coverage.out coverage.html bench.txt
	rm -rf packages/admin/build packages/admin/.svelte-kit
	rm -rf internal/admin/ui/dist
	mkdir -p internal/admin/ui/dist
	touch internal/admin/ui/dist/.gitkeep
