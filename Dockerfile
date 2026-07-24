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
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.buildVersion=${VERSION}" -o /out/ydn64 ./cmd/ydn64

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/ydn64 /usr/local/bin/ydn64
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Persist the generated identity (PrivateKey) and derived Nat64Pool/Dns64Listen
# addresses across restarts by mounting a volume at /data — otherwise the
# entrypoint generates a brand new config (and Yggdrasil identity) every
# container start. See README.md "Running with Docker" for details.
VOLUME ["/data"]
ENV YDN64_CONFIG=/data/ydn64.conf

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
