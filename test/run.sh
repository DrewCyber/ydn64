#!/bin/sh
# Black-box test harness orchestrator for ydn64, using podman.
#
# Topology:
#
#   [target: IPv4-only httpd+dnsmasq] --targetnet(NAT'd bridge)-- [A: ydn64]
#                                                                     |
#                                                              yggnet(--internal)
#                                                                     |
#                                            [B: real upstream yggdrasil-go, TUN]
#
# B only has an interface on the `--internal` yggnet network — no route to
# the outside world at all, simulating "a device with only Yggdrasil
# connectivity". A additionally sits on targetnet, giving it (and only it)
# IPv4 reachability to the fake `target` host, exactly like a real ydn64
# gateway with internet access on one side and Yggdrasil peers on the other.
#
# Usage: ./run.sh <command>
#   build      build all three container images
#   netup      create the two podman networks
#   up         generate configs + start target, A, B (implies build/netup)
#   wait       block until B has peered with A
#   test       run every script in cases/ in order (implies up + wait)
#   logs <ct>  tail podman logs for a/b/target (also see .run/*.log)
#   down       stop + remove containers
#   netdown    remove the two podman networks
#   clean      down + netdown + remove .run/ generated files
#   all        build + up + wait + test

set -eu
. "$(dirname -- "$0")/lib.sh"

cmd_build() {
  log "building images..."
  $PODMAN build -t "$IMAGE_YDN64" -f "$TEST_DIR/Containerfile.ydn64" "$ROOT_DIR"
  $PODMAN build -t "$IMAGE_CLIENT" -f "$TEST_DIR/Containerfile.yggclient" "$TEST_DIR"
  $PODMAN build -t "$IMAGE_TARGET" -f "$TEST_DIR/Containerfile.target" "$TEST_DIR"
}

cmd_netup() {
  $PODMAN network exists "$NET_TARGET" 2>/dev/null || {
    log "creating network $NET_TARGET ($SUBNET_TARGET, NAT'd)"
    $PODMAN network create --subnet "$SUBNET_TARGET" "$NET_TARGET"
  }
  $PODMAN network exists "$NET_YGG" 2>/dev/null || {
    log "creating network $NET_YGG ($SUBNET_YGG, --internal, no egress)"
    $PODMAN network create --internal --subnet "$SUBNET_YGG" "$NET_YGG"
  }
}

cmd_netdown() {
  $PODMAN network rm "$NET_YGG" >/dev/null 2>&1 || true
  $PODMAN network rm "$NET_TARGET" >/dev/null 2>&1 || true
}

cmd_down() {
  for ct in "$CT_B" "$CT_A" "$CT_TARGET"; do
    $PODMAN rm -f "$ct" >/dev/null 2>&1 || true
  done
}

genconfs() {
  mkdir -p "$RUN_DIR"
  log "generating A (ydn64) config..."
  ( cd "$ROOT_DIR" && go run ./test/gen \
      -role=ydn64 \
      -listen="tcp://0.0.0.0:${YGG_PORT}" \
      -peers="$YDN64_REAL_PEER" \
      -allowed-sources="${YDN64_ALLOWED_SOURCES:-200::/7}" \
      -dns64-default="${IP_TARGET}:53" \
      -dns64-invalid="${YDN64_DNS64_INVALID:-ignore}" \
      -out="$RUN_DIR/ydn64.conf" \
      -envout="$RUN_DIR/ydn64.env" )

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

  log "starting target..."
  $PODMAN run -d --name "$CT_TARGET" \
    --network "${NET_TARGET}:ip=${IP_TARGET}" \
    -e TARGET_IP="$IP_TARGET" \
    "$IMAGE_TARGET" >/dev/null

  log "starting A (ydn64)..."
  $PODMAN run -d --name "$CT_A" \
    --network "${NET_YGG}:ip=${IP_A_YGG}" \
    --cap-add=NET_RAW \
    -v "$RUN_DIR:/work:Z" \
    "$IMAGE_YDN64" -useconffile /work/ydn64.conf -logto /work/ydn64.log -loglevel debug >/dev/null
  $PODMAN network connect "$NET_TARGET" --ip "$IP_A_TARGET" "$CT_A"

  log "starting B (yggdrasil-go, TUN + CAP_NET_ADMIN)..."
  $PODMAN run -d --name "$CT_B" \
    --network "${NET_YGG}:ip=${IP_B_YGG}" \
    --cap-add=NET_ADMIN --cap-add=NET_RAW --device=/dev/net/tun \
    -v "$RUN_DIR:/work:Z" \
    "$IMAGE_CLIENT" -useconffile /work/yggclient.conf -logto /work/yggclient.log -loglevel debug >/dev/null
}

cmd_wait() {
  wait_for 30 "B has an active peer" \
    sh -c "$PODMAN exec $CT_B yggdrasilctl -json getpeers | grep -q '\"up\": true'"
}

cmd_test() {
  cmd_up
  cmd_wait
  # shellcheck disable=SC1090
  . "$RUN_DIR/ydn64.env"
  export NODE_ADDR DNS64_LISTEN DNS64_LISTEN_ADDR NAT64_POOL_PREFIX NAT64_POOL_CIDR

  failures=0
  for case_script in "$TEST_DIR"/cases/*.sh; do
    log "=== running $(basename "$case_script") ==="
    if ! sh "$case_script"; then
      warn "case FAILED: $(basename "$case_script")"
      failures=$((failures + 1))
    fi
  done

  if [ "$failures" -gt 0 ]; then
    fail "$failures test case(s) failed"
  fi
  log "all test cases passed"
}

cmd_logs() {
  ct="${1:?usage: run.sh logs <a|b|target>}"
  case "$ct" in
    a) $PODMAN logs -f "$CT_A" ;;
    b) $PODMAN logs -f "$CT_B" ;;
    target) $PODMAN logs -f "$CT_TARGET" ;;
    *) fail "unknown container '$ct' (expected a|b|target)" ;;
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
  logs)    shift; cmd_logs "$@" ;;
  down)    cmd_down ;;
  clean)   cmd_clean ;;
  all)     cmd_all ;;
  *)
    echo "usage: $0 {build|netup|netdown|up|wait|test|logs <a|b|target>|down|clean|all}" >&2
    exit 1
    ;;
esac
