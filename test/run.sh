#!/bin/sh
# Black-box test harness orchestrator for ydn64, using podman.
#
# Topology:
#
#                                                              [A: ydn64]
#                                                               /       \
#                                                       yggnet(--internal)  egressnet(NAT'd bridge)
#                                                             /                    \
#                                    [B: real upstream yggdrasil-go, TUN]      (real internet)
#
# B only has an interface on the `--internal` yggnet network — no route to
# the outside world at all, simulating "a device with only Yggdrasil
# connectivity", statically peered to A. A additionally sits on egressnet
# (a normal NAT'd bridge), giving it (and only it) real internet
# reachability — real-world DNS forwarders, real Yggdrasil peers, and a
# real Alfis .ygg DNS server are all reached through it. There is no local
# fake IPv4 target: every test case that needs a name to resolve uses a
# real-world one (dns.google, howto.ygg, ...).
#
# Usage: ./run.sh <command>
#   build       build the two container images
#   netup       create the two podman networks
#   up          generate configs + start A, B (implies build/netup)
#   wait        block until B has peered with A
#   test        run every script in cases/ in order (implies up + wait)
#   case <name> boot a fresh baseline environment and run just one case
#               (implies up + wait); <name> is a cases/*.sh filename, with
#               or without its .sh extension
#   logs <ct>   tail podman logs for a/b (also see .run/*.log)
#   down        stop + remove containers
#   netdown     remove the two podman networks
#   clean       down + netdown + remove .run/ generated files
#   all         build + up + wait + test

set -eu
. "$(dirname -- "$0")/lib.sh"

cmd_build() {
  log "building images..."
  $PODMAN build -t "$IMAGE_YDN64" -f "$TEST_DIR/Containerfile.ydn64" "$ROOT_DIR"
  $PODMAN build -t "$IMAGE_CLIENT" -f "$TEST_DIR/Containerfile.yggclient" "$TEST_DIR"
}

cmd_netup() {
  $PODMAN network exists "$NET_EGRESS" 2>/dev/null || {
    log "creating network $NET_EGRESS ($SUBNET_EGRESS, NAT'd)"
    $PODMAN network create --subnet "$SUBNET_EGRESS" "$NET_EGRESS"
  }
  $PODMAN network exists "$NET_YGG" 2>/dev/null || {
    log "creating network $NET_YGG ($SUBNET_YGG, --internal, no egress)"
    $PODMAN network create --internal --subnet "$SUBNET_YGG" "$NET_YGG"
  }
}

cmd_netdown() {
  $PODMAN network rm "$NET_YGG" >/dev/null 2>&1 || true
  $PODMAN network rm "$NET_EGRESS" >/dev/null 2>&1 || true
}

cmd_down() {
  for ct in "$CT_B" "$CT_A"; do
    $PODMAN rm -f "$ct" >/dev/null 2>&1 || true
  done
}

genconfs() {
  mkdir -p "$RUN_DIR"
  log "generating A (ydn64) config..."
  ( cd "$ROOT_DIR" && go run ./test/gen \
      -role=ydn64 \
      -listen="tcp://0.0.0.0:${YGG_PORT}" \
      -peers="$YDN64_REAL_PEERS" \
      -allowed-sources="${YDN64_ALLOWED_SOURCES:-200::/7}" \
      -dns64-invalid="${YDN64_DNS64_INVALID:-ignore}" \
      -out="$RUN_DIR/ydn64.conf" \
      -envout="$RUN_DIR/ydn64.env" )
  cp "$RUN_DIR/ydn64.conf" "$RUN_DIR/ydn64.conf.baseline"

  log "generating B (yggdrasil-go client) config..."
  ( cd "$ROOT_DIR" && go run ./test/gen \
      -role=client \
      -peers="tcp://${IP_A_YGG}:${YGG_PORT}?maxbackoff=5s" \
      -out="$RUN_DIR/yggclient.conf" \
      -envout="$RUN_DIR/yggclient.env" )

  # shellcheck disable=SC1090
  . "$RUN_DIR/ydn64.env"
  log "A node address   : $NODE_ADDR"
  log "A DNS64 listen   : $DNS64_LISTEN"
  log "A NAT64 pool     : $NAT64_POOL_CIDR"
}

cmd_up() {
  cmd_build
  cmd_netup
  genconfs
  : >"$RUN_DIR/ydn64.log"
  : >"$RUN_DIR/yggclient.log"

  cmd_down

  log "starting A (ydn64)..."
  $PODMAN run -d --name "$CT_A" \
    --network "${NET_YGG}:ip=${IP_A_YGG}" \
    --cap-add=NET_RAW \
    -v "$RUN_DIR:/work:Z" \
    "$IMAGE_YDN64" -useconffile /work/ydn64.conf -logto /work/ydn64.log -loglevel debug >/dev/null
  $PODMAN network connect "$NET_EGRESS" --ip "$IP_A_EGRESS" "$CT_A"

  log "starting B (yggdrasil-go, TUN + CAP_NET_ADMIN)..."
  # DNS64_SERVER points B's own /etc/resolv.conf at A's DNS64 listener (see
  # test/yggclient-entrypoint.sh), so case scripts can `dig <name>` without
  # an explicit @server — though most still pin @server explicitly anyway,
  # to keep assertions independent of resolv.conf timing/search-domain
  # behavior.
  $PODMAN run -d --name "$CT_B" \
    --network "${NET_YGG}:ip=${IP_B_YGG}" \
    --cap-add=NET_ADMIN --cap-add=NET_RAW --device=/dev/net/tun \
    -e "DNS64_SERVER=${DNS64_LISTEN_ADDR}" \
    -v "$RUN_DIR:/work:Z" \
    "$IMAGE_CLIENT" -useconffile /work/yggclient.conf -logto /work/yggclient.log -loglevel debug >/dev/null
}

cmd_wait() {
  wait_for 30 "B has an active peer" \
    sh -c "$PODMAN exec $CT_B yggdrasilctl -json getpeers | grep -q '\"up\": true'"
}

# export_env sources ydn64.env and exports the vars every case script relies
# on. Factored out so both cmd_test and cmd_case set up identically.
export_env() {
  # shellcheck disable=SC1090
  . "$RUN_DIR/ydn64.env"
  export NODE_ADDR DNS64_LISTEN DNS64_LISTEN_ADDR NAT64_POOL_PREFIX NAT64_POOL_CIDR
}

cmd_test() {
  cmd_up
  cmd_wait
  export_env

  failures=0
  for case_script in "$TEST_DIR"/cases/*.sh; do
    if ! run_case "$case_script"; then
      warn "case FAILED: $(basename "$case_script")"
      failures=$((failures + 1))
    fi
  done

  if [ "$failures" -gt 0 ]; then
    fail "$failures test case(s) failed"
  fi
  log "all test cases passed"
}

cmd_case() {
  name="${1:?usage: run.sh case <name>}"
  case_script="$TEST_DIR/cases/$name"
  [ -f "$case_script" ] || case_script="$TEST_DIR/cases/${name}.sh"
  [ -f "$case_script" ] || fail "no such case: $1"

  cmd_up
  cmd_wait
  export_env

  run_case "$case_script" || fail "case FAILED: $(basename "$case_script")"
  log "case passed: $(basename "$case_script")"
}

cmd_logs() {
  ct="${1:?usage: run.sh logs <a|b>}"
  case "$ct" in
    a) $PODMAN logs -f "$CT_A" ;;
    b) $PODMAN logs -f "$CT_B" ;;
    *) fail "unknown container '$ct' (expected a|b)" ;;
  esac
}

cmd_clean() {
  cmd_down
  cmd_netdown
  rm -rf "$RUN_DIR"
}

cmd_all() {
  cmd_test
}

case "${1:-}" in
  build)   cmd_build ;;
  netup)   cmd_netup ;;
  netdown) cmd_netdown ;;
  up)      cmd_up ;;
  wait)    cmd_wait ;;
  test)    cmd_test ;;
  case)    shift; cmd_case "$@" ;;
  logs)    shift; cmd_logs "$@" ;;
  down)    cmd_down ;;
  clean)   cmd_clean ;;
  all)     cmd_all ;;
  *)
    echo "usage: $0 {build|netup|netdown|up|wait|test|case <name>|logs <a|b>|down|clean|all}" >&2
    exit 1
    ;;
esac
