# syntax=docker/dockerfile:1

FROM golang:1.26.6-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
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
