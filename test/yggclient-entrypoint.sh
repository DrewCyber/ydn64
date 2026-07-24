#!/bin/sh
# Thin entrypoint wrapper for the yggclient (B) test image.
#
# If DNS64_SERVER is set (A's DNS64 IPv6 listen address, passed in by
# test/run.sh once A's config has been generated), point this container's
# resolver at it so plain `dig <name>` / getaddrinfo() calls default to A's
# DNS64 service without needing an explicit `@server`. Falls through to
# whatever resolv.conf podman already set up if DNS64_SERVER is unset.
set -eu
if [ -n "${DNS64_SERVER:-}" ]; then
  printf 'nameserver %s\n' "$DNS64_SERVER" >/etc/resolv.conf
fi
exec yggdrasil "$@"
