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

NET_YGG=ydn64-test-yggnet       # internal: simulates "yggdrasil-only, no internet"
NET_EGRESS=ydn64-test-egressnet # normal bridge: gives A (and only A) real internet egress

SUBNET_YGG=10.90.0.0/24
SUBNET_EGRESS=10.89.0.0/24

IP_A_YGG=10.90.0.2
IP_B_YGG=10.90.0.3
IP_A_EGRESS=10.89.0.10

CT_A=ydn64-test-a
CT_B=ydn64-test-b

YGG_PORT=9993

# Real outbound peers connecting A to the actual Yggdrasil network (over its
# egressnet/internet egress), needed for test/cases/02_dns_google_icmp.sh and
# test/cases/03_ygg_zone_resolution.sh (the latter reaches a real Alfis DNS
# forwarder at [308:84:68:55::]:53). Same addresses used as sample peers in
# the checked-in ydn64.conf. Comma-separated, fed straight into test/gen's
# -peers flag. At least one of the two is expected to be reachable at any
# given time — tests tolerate one being briefly unreachable.
YDN64_REAL_PEERS=${YDN64_REAL_PEERS:-tcp://37.186.113.100:1514,tcp://vpn.itrus.su:7991}

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

# reload_a <description>
# Sends SIGHUP to the running A (ydn64) container to trigger a live config
# reload (AllowedSources; DNS64 zones/default forwarder/InvalidAddress/cache
# settings; Nat64UdpTimeout — see reloadConfig() in cmd/ydn64/main.go) and
# waits for the resulting "config reloaded" line to appear in A's log.
#
# Assumes $RUN_DIR/ydn64.conf has already been rewritten with the desired
# change. Unlike the old `podman restart` approach this never tears down
# A's process or its Yggdrasil peering with B, so there is no re-peering
# wait and none of the podman-restart re-peering flakiness documented in
# AGENTS.md — the reload is applied in place, in well under a second.
reload_a() {
  desc=$1
  before=$(wc -l <"$RUN_DIR/ydn64.log" 2>/dev/null || echo 0)
  $PODMAN kill --signal HUP "$CT_A" >/dev/null
  wait_for 10 "$desc" \
    sh -c "tail -n +\$(($before + 1)) '$RUN_DIR/ydn64.log' 2>/dev/null | grep -q 'config reloaded'"
}

# run_case <case_script_path>
# Runs one case script and unconditionally restores A back to the baseline
# config ($RUN_DIR/ydn64.conf.baseline, snapshotted once by run.sh right
# after config generation) afterwards, live-reloading via SIGHUP if the
# case left A's config file modified. This is what makes cases independent
# of each other and re-runnable in isolation (`run.sh case <name>`): a case
# is free to rewrite $RUN_DIR/ydn64.conf and call reload_a as many times as
# it likes to exercise a config change, without needing its own backup/
# restore/trap logic — the harness always resets to the same starting
# point before returning, regardless of whether the case passed or failed.
# Returns the case script's own exit status.
run_case() {
  case_script=$1
  log "=== running $(basename "$case_script") ==="
  status=0
  sh "$case_script" || status=$?
  if ! cmp -s "$RUN_DIR/ydn64.conf" "$RUN_DIR/ydn64.conf.baseline"; then
    cp "$RUN_DIR/ydn64.conf.baseline" "$RUN_DIR/ydn64.conf"
    reload_a "A restored baseline config after $(basename "$case_script")"
  fi
  return "$status"
}

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
