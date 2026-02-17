#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
EXAMPLES_DIR="$ROOT_DIR/tools/examples"

v1_fail="$EXAMPLES_DIR/lifecycle_summary_v1_failed.json"
v2_ok="$EXAMPLES_DIR/lifecycle_summary_v2_ok.json"
v3_ok="$EXAMPLES_DIR/lifecycle_summary_v3_ok.json"

for f in "$v1_fail" "$v2_ok" "$v3_ok"; do
	jq -e . "$f" >/dev/null
done

flat_required='[
  "schema_version","status","reason","worker","last_step","last_tx",
  "tx_register","tx_request_unbonding","tx_finalize_unbonding",
  "start_height","end_height","height_delta","duration_s",
  "release_height","cooldown_waited_blocks","cooldown_stagnant_rounds",
  "node_height","catching_up"
]'

jq -e --argjson req "$flat_required" '
  .schema_version == 2 and
  ((keys - $req) | length) == 0 and
  (($req - keys) | length) == 0 and
  (.status == "ok") and
  (has("phase_txs") | not) and
  (has("timing") | not) and
  (has("node") | not)
' "$v2_ok" >/dev/null

jq -e --argjson req "$flat_required" '
  .schema_version == 3 and
  (($req - keys) | length) == 0 and
  (.phase_txs | type == "object") and
  (.timing | type == "object") and
  (.node | type == "object") and
  .phase_txs.register == .tx_register and
  .phase_txs.request_unbonding == .tx_request_unbonding and
  .phase_txs.finalize_unbonding == .tx_finalize_unbonding and
  .timing.start_height == .start_height and
  .timing.end_height == .end_height and
  .timing.height_delta == .height_delta and
  .timing.duration_s == .duration_s and
  .timing.release_height == .release_height and
  .timing.cooldown_waited_blocks == .cooldown_waited_blocks and
  .timing.cooldown_stagnant_rounds == .cooldown_stagnant_rounds and
  .node.height == .node_height and
  (.node.catching_up|tostring) == (.catching_up|tostring)
' "$v3_ok" >/dev/null

jq -e --argjson req "$flat_required" '
  .schema_version == 1 and
  (($req - keys) | length) == 0 and
  (.status == "failed") and
  (.reason | startswith("finalize-unbonding broadcast failed"))
' "$v1_fail" >/dev/null

echo "PASS: lifecycle summary fixtures consistent with schema contract"
