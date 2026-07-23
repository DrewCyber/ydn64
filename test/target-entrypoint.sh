#!/bin/sh
set -eu

: "${TARGET_IP:?TARGET_IP env var required (this container's own IPv4 address)}"

# Authoritative-only resolver: answers target.test with our own IP, refuses
# everything else. No upstream/-no-resolv so it never leaks to real DNS.
dnsmasq --no-daemon --no-resolv --no-hosts \
  --address="/target.test/${TARGET_IP}" &

exec httpd -f -h /www -p 80
