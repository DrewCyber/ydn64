#!/bin/sh
# Entrypoint for the ydn64 Docker image.
#
# On first run (no config file at $YDN64_CONFIG yet) it generates one via
# `ydn64 -genconf`, so PrivateKey/Nat64Pool/Dns64Listen are pre-derived and
# stable for as long as the config file persists (mount /data as a volume to
# keep the same Yggdrasil identity across container restarts). If a config
# file already exists at $YDN64_CONFIG, it is left as-is — env var overrides
# below still apply on top of it.
#
# PrivateKey, Peers and AllowedSources can be supplied via the
# YDN64_PRIVATE_KEY / YDN64_PEERS / YDN64_ALLOWED_SOURCES environment
# variables (comma and/or whitespace separated for the latter two), which
# ydn64 applies as overrides on top of the loaded config file at startup. If
# all three are set on first run (no config file yet), `ydn64 -genconf` also
# bakes them directly into the generated file — so a container can run with
# a fully working identity/peers/allowlist from env vars alone, with no
# config file or volume required at all. See README.md for details.
set -eu

CONFIG_PATH="${YDN64_CONFIG:-/data/ydn64.conf}"

if [ ! -f "$CONFIG_PATH" ]; then
    echo "ydn64: no config found at $CONFIG_PATH, generating one..." >&2
    mkdir -p "$(dirname "$CONFIG_PATH")"
    ydn64 -genconf > "$CONFIG_PATH"
fi

exec ydn64 -useconffile "$CONFIG_PATH" "$@"
