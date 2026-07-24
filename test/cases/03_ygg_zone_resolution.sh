#!/bin/sh
# Real-world .ygg zone forwarding check, exercising A's real outbound peers
# (see YDN64_REAL_PEERS in lib.sh) to reach a genuine Alfis DNS server at
# [308:84:68:55::]:53 over the actual Yggdrasil network.
#
# 1. B resolves a well-known .ygg name through A's DNS64 (default/baseline
#    config); the answer(s) must fall inside 200::/7 (Yggdrasil's real
#    address range) — proving return-ipv6-addresses passes real
#    Yggdrasil-native AAAA answers through with no special-casing of
#    200::/7 anywhere in the DNS64 code path.
# 2. A's config is reloaded (SIGHUP, no restart) with the .ygg zone stripped
#    from its config (test/gen's -ygg-zone=false) and the same query must
#    now return no AAAA answer. The always-present "." catch-all zone still
#    technically matches .ygg names, but with return-ipv6 disabled and no
#    real A record for howto.ygg from the default forwarder, it can't
#    synthesise or pass through any real address — proving the
#    .ygg-specific 200::/7 pass-through only happens when that zone exists.
#
# No manual config restore at the end: run.sh's run_case() diffs A's config
# against the baseline snapshot and restores+reloads automatically once this
# script exits, regardless of pass/fail — see lib.sh.
#
# This case requires real internet + real Yggdrasil network egress from the
# A container. If A's environment has no such access, this case will fail —
# that is expected and intentional, not a flake to be relaxed.
set -eu
. "$(dirname -- "$0")/../lib.sh"

: "${DNS64_LISTEN_ADDR:?}"

YGG_DOMAIN=howto.ygg

# assert_in_ygg_range <ipv6-addr> <desc>
# Checks that the first hextet of an IPv6 address falls within 0200::/9's
# 16-bit-group range 0x0200-0x03ff (i.e. the 200::/7 Yggdrasil range).
assert_in_ygg_range() {
  addr=$1; desc=$2
  first_group=$(printf '%s' "$addr" | cut -d: -f1)
  val=$(printf '%d' "0x$first_group" 2>/dev/null) || fail "FAIL: $desc: not a hex group ($addr)"
  if [ "$val" -ge 512 ] && [ "$val" -le 1023 ]; then
    log "PASS: $desc ($addr is in 200::/7)"
  else
    fail "FAIL: $desc: $addr is not in 200::/7"
  fi
}

# Real-world Yggdrasil routing convergence to a distant node can take a few
# seconds after A's peer connections come up, so retry before failing.
dig_ygg() {
  n=0
  answer=""
  while [ "$n" -lt 10 ]; do
    answer=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" AAAA "$YGG_DOMAIN" +short +time=5 +tries=2 2>/dev/null | grep -v '^;' | grep -v '^$' || true)
    [ -n "$answer" ] && break
    n=$((n + 1))
    sleep 2
  done
}

dig_ygg
log "dig AAAA ${YGG_DOMAIN} -> ${answer}"
[ -n "$answer" ] || fail "FAIL: no AAAA answer from DNS64 for ${YGG_DOMAIN} (real Yggdrasil network egress required)"

echo "$answer" | while IFS= read -r addr; do
  [ -n "$addr" ] || continue
  assert_in_ygg_range "$addr" "AAAA answer for ${YGG_DOMAIN} falls under 200::/7"
done

log "reloading A with the .ygg zone removed..."
( cd "$ROOT_DIR" && go run ./test/gen \
    -role=ydn64 \
    -listen="tcp://0.0.0.0:${YGG_PORT}" \
    -peers="$YDN64_REAL_PEERS" \
    -allowed-sources="${YDN64_ALLOWED_SOURCES:-200::/7}" \
    -dns64-invalid="${YDN64_DNS64_INVALID:-ignore}" \
    -ygg-zone=false \
    -out="$RUN_DIR/ydn64.conf" \
    -envout="$RUN_DIR/ydn64.env.tmp" )
rm -f "$RUN_DIR/ydn64.env.tmp"
reload_a "A reloaded config (.ygg zone removed)"

# Even though there's no restart/re-peering to wait for here, the zone
# change still needs to actually take effect before the next query — same
# defensive retry as this case uses for the initial lookup.
n=0
dig_out=""
while [ "$n" -lt 10 ]; do
  dig_out=$($PODMAN exec "$CT_B" dig "@${DNS64_LISTEN_ADDR}" AAAA "$YGG_DOMAIN" +time=5 +tries=2 2>&1 || true)
  case "$dig_out" in
    *"ANSWER: 0"*|*"status: NXDOMAIN"*) break ;;
  esac
  n=$((n + 1))
  sleep 2
done
log "dig AAAA ${YGG_DOMAIN} (no .ygg zone) ->\n${dig_out}"
assert_contains "$dig_out" "ANSWER: 0" "no .ygg zone -> no AAAA answer for ${YGG_DOMAIN}"

log "PASS: .ygg zone resolves real 200::/7 answers, and returns no AAAA answer when the zone is absent"
