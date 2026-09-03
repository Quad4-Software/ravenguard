# syntax=docker/dockerfile:1

FROM node:22-bookworm AS admin
WORKDIR /src
RUN corepack enable && corepack prepare pnpm@11.24.0 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/admin/package.json packages/admin/
RUN pnpm install --frozen-lockfile --filter @quad4/ravenguard-admin...
COPY packages/admin packages/admin
COPY Makefile ./
RUN pnpm admin:build \
	&& rm -rf internal/admin/ui/dist \
	&& mkdir -p internal/admin/ui/dist \
	&& cp -a packages/admin/build/. internal/admin/ui/dist/ \
	&& touch internal/admin/ui/dist/.gitkeep

FROM golang:1.26.6-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=admin /src/internal/admin/ui/dist/ ./internal/admin/ui/dist/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ravenguard ./cmd/ravenguard

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/ravenguard /ravenguard
COPY deploy/seccomp-ravenguard.json /etc/ravenguard/seccomp.json
USER nonroot:nonroot
EXPOSE 80 443/tcp 443/udp 8080 8443/tcp 8443/udp
# Container runtime should allow landlock_* and seccomp syscalls
# (see deploy/seccomp-ravenguard.json and docker-compose security_opt).
# In-process Landlock + seccomp-bpf apply when sandbox.mode is not off.
ENTRYPOINT ["/ravenguard"]
CMD ["-config", "/config/ravenguard.toml"]
