#!/bin/sh
# Entrypoint for the ydn64 Docker image.
#
# On first run (no config file at $YDN64_CONFIG yet) it generates one via
# `ydn64 -genconf`, so PrivateKey/Nat64Pool/Dns64Listen are pre-derived and
# stable for as long as the config file persists (mount /data as a volume to
# keep the same Yggdrasil identity across container restarts).
#
# Peers and AllowedSources are normally the only two fields you must set —
# do so via the YDN64_PEERS / YDN64_ALLOWED_SOURCES environment variables
# (comma and/or whitespace separated), which ydn64 applies as overrides on
# top of the loaded config file at startup. See README.md for details.
set -eu

CONFIG_PATH="${YDN64_CONFIG:-/data/ydn64.conf}"

if [ ! -f "$CONFIG_PATH" ]; then
    echo "ydn64: no config found at $CONFIG_PATH, generating one..." >&2
    mkdir -p "$(dirname "$CONFIG_PATH")"
    ydn64 -genconf > "$CONFIG_PATH"
fi

exec ydn64 -useconffile "$CONFIG_PATH" "$@"
