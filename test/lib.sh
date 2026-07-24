#!/bin/sh
# Shared config/constants + helper functions for the black-box test harness.
# Sourced by run.sh and cases/*.sh — must stay POSIX sh (no bashisms) since
# it also runs fine under podman's alpine-based `sh` when sourced indirectly
# via podman exec wrappers.

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$TEST_DIR" in
  */cases) TEST_DIR=$(dirname -- "$TEST_DIR") ;;
esac
ROOT_DIR=$(dirname -- "$TEST_DIR")
RUN_DIR="$TEST_DIR/.run"

PODMAN=${PODMAN:-podman}

IMAGE_YDN64=ydn64-test-ydn64
IMAGE_CLIENT=ydn64-test-yggclient
IMAGE_TARGET=ydn64-test-target

NET_YGG=ydn64-test-yggnet       # internal: simulates "yggdrasil-only, no internet"
NET_TARGET=ydn64-test-targetnet # normal bridge: gives A (and only A) IPv4 egress

SUBNET_YGG=10.90.0.0/24
SUBNET_TARGET=10.89.0.0/24

IP_A_YGG=10.90.0.2
IP_B_YGG=10.90.0.3
IP_A_TARGET=10.89.0.10
IP_TARGET=10.89.0.2

CT_A=ydn64-test-a
CT_B=ydn64-test-b
CT_TARGET=ydn64-test-target

YGG_PORT=9993

# Real outbound peer connecting A to the actual Yggdrasil network (over its
# targetnet/internet egress), needed for test/cases/06_ygg_zone_resolution.sh
# to reach a real Alfis DNS forwarder at [308:84:68:55::]:53. Same address
# used as the sample peer in the checked-in ydn64.conf.
YDN64_REAL_PEER=${YDN64_REAL_PEER:-tcp://37.186.113.100:1514}

log()  { printf '\033[1;34m[test]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[test]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[test]\033[0m %s\n' "$*" >&2; exit 1; }

# wait_for <timeout_seconds> <description> <command...>
# Retries <command...> every second until it exits 0, or fails after timeout.
wait_for() {
  timeout=$1; desc=$2; shift 2
  n=0
  while [ "$n" -lt "$timeout" ]; do
    if "$@" >/dev/null 2>&1; then
      log "ready: $desc (after ${n}s)"
      return 0
    fi
    n=$((n + 1))
    sleep 1
  done
  fail "timed out after ${timeout}s waiting for: $desc"
}

exec_b() { $PODMAN exec "$CT_B" "$@"; }
exec_a_logs() { $PODMAN logs "$CT_A" "$@"; }

assert_contains() {
  haystack=$1; needle=$2; desc=$3
  case "$haystack" in
    *"$needle"*) log "PASS: $desc" ;;
    *) fail "FAIL: $desc\n  expected to contain: $needle\n  got: $haystack" ;;
  esac
}

assert_not_contains() {
  haystack=$1; needle=$2; desc=$3
  case "$haystack" in
    *"$needle"*) fail "FAIL: $desc\n  expected NOT to contain: $needle\n  got: $haystack" ;;
    *) log "PASS: $desc" ;;
  esac
}
