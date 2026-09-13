# syntax=docker/dockerfile:1

FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG REVISION=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
	-ldflags="-s -w -X github.com/Quad4-Software/ravenguard/internal/version.Commit=${REVISION} -X github.com/Quad4-Software/ravenguard/internal/version.Version=${VERSION}" \
	-o /out/ravenguard ./cmd/ravenguard

# Distroless static nonroot (UID/GID 65532). Suitable for rootless runtimes.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

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
