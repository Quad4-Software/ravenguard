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

FROM golang:1.27.1-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=admin /src/internal/admin/ui/dist/ ./internal/admin/ui/dist/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ravenguard ./cmd/ravenguard

# Distroless static nonroot (UID/GID 65532). Suitable for rootless runtimes.
FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
ARG SOURCE=https://github.com/Quad4-Software/ravenguard

LABEL org.opencontainers.image.title="RavenGuard" \
	org.opencontainers.image.description="HTTP WAF and reverse proxy" \
	org.opencontainers.image.url="https://github.com/Quad4-Software/ravenguard" \
	org.opencontainers.image.documentation="https://github.com/Quad4-Software/ravenguard/tree/master/docs" \
	org.opencontainers.image.source="${SOURCE}" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.revision="${REVISION}" \
	org.opencontainers.image.created="${CREATED}" \
	org.opencontainers.image.licenses="0BSD" \
	org.opencontainers.image.vendor="Quad4 Software" \
	org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot"

WORKDIR /
COPY --from=build /out/ravenguard /ravenguard
COPY deploy/seccomp-ravenguard.json /etc/ravenguard/seccomp.json

# Explicit nonroot identity (distroless nonroot is 65532:65532).
USER 65532:65532

EXPOSE 80 443/tcp 443/udp 8080 8443/tcp 8443/udp
# Container runtime should allow landlock_* and seccomp syscalls
# (see deploy/seccomp-ravenguard.json and docker-compose security_opt).
# In-process Landlock + seccomp-bpf apply when sandbox.mode is not off.
ENTRYPOINT ["/ravenguard"]
CMD ["-config", "/config/ravenguard.toml"]
