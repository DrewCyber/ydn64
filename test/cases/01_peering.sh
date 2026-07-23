#!/bin/sh
# Sanity check: B (real yggdrasil-go) has an active peering to A (ydn64)
# over the internal yggnet. Also exercised by `run.sh wait`, kept here too
# so `run.sh test` reports it as its own pass/fail case.
set -eu
. "$(dirname -- "$0")/../lib.sh"

peers=$($PODMAN exec "$CT_B" yggdrasilctl -json getpeers)
assert_contains "$peers" '"up": true' "B has at least one active peer (A)"
