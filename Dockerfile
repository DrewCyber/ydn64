# syntax=docker/dockerfile:1

# Multi-arch production image for ydn64. Built by the "docker" job in
# .github/workflows/release.yml (which also builds Linux binaries).
# for linux/amd64 and linux/arm64, published to ghcr.io on version tags.
#
# Cross-compiles natively (no QEMU emulation of the Go toolchain itself):
# the build stage always runs on $BUILDPLATFORM and cross-compiles to
# $TARGETOS/$TARGETARCH via Go's own GOOS/GOARCH, which is far faster than
# emulating the compiler under QEMU.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY src ./src
COPY tools ./tools
COPY LICENSE /out/LICENSE
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.buildVersion=${VERSION}" -o /out/ydn64 ./cmd/ydn64
# TARGETOS/TARGETARCH leak into RUN as env vars and would make "go run" build
# the generator for the target platform; unset them so it runs natively.
RUN env -u GOOS -u GOARCH go run ./tools/licenses -o /out/THIRD-PARTY-NOTICES.txt

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
    && addgroup -g 10001 ydn64 \
    && adduser -D -H -u 10001 -G ydn64 ydn64 \
    && mkdir -p /data && chown ydn64:ydn64 /data
COPY --from=build /out/ydn64 /usr/local/bin/ydn64
COPY --from=build /out/THIRD-PARTY-NOTICES.txt /usr/local/share/doc/ydn64/THIRD-PARTY-NOTICES.txt
COPY --from=build /out/LICENSE /usr/local/share/doc/ydn64/LICENSE
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Persist the generated identity (PrivateKey) and derived Nat64Pool/Dns64Listen
# addresses across restarts by mounting a volume at /data — otherwise the
# entrypoint generates a brand new config (and Yggdrasil identity) every
# container start. See README.md "Running with Docker" for details.
#
# Runs as a dedicated non-root user: everything ydn64 does is userspace
# (gVisor netstack binds port 53 without privileges); CAP_NET_RAW for ICMP
# NAT64 can be granted to this user via `--cap-add=NET_RAW`. Mounted volumes
# must be writable by UID 10001, or pass `--user=0` and accept a root process.
VOLUME ["/data"]
ENV YDN64_CONFIG=/data/ydn64.conf
USER 10001:10001

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
