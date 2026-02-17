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

CONTRACT_JSON="$ROOT_DIR/tools/lifecycle_summary_schema_contract.json"
flat_required="$(jq -c '.flat_required' "$CONTRACT_JSON")"
v3_phase_required="$(jq -c '.v3_nested.phase_txs' "$CONTRACT_JSON")"
v3_timing_required="$(jq -c '.v3_nested.timing' "$CONTRACT_JSON")"
v3_node_required="$(jq -c '.v3_nested.node' "$CONTRACT_JSON")"
v3_nested_required='["phase_txs","timing","node"]'

jq -e --argjson req "$flat_required" '
  .schema_version == 2 and
  ((keys - $req) | length) == 0 and
  (($req - keys) | length) == 0 and
  (.status == "ok") and
  (has("phase_txs") | not) and
  (has("timing") | not) and
  (has("node") | not)
' "$v2_ok" >/dev/null

jq -e \
  --argjson req "$flat_required" \
  --argjson nested_req "$v3_nested_required" \
  --argjson phase_req "$v3_phase_required" \
  --argjson timing_req "$v3_timing_required" \
  --argjson node_req "$v3_node_required" '
  .schema_version == 3 and
  (($req - keys) | length) == 0 and
  ((keys - ($req + $nested_req)) | length) == 0 and
  (.phase_txs | type == "object") and
  (.timing | type == "object") and
  (.node | type == "object") and
  ((.phase_txs | keys) - $phase_req | length) == 0 and
  (($phase_req - (.phase_txs | keys)) | length) == 0 and
  ((.timing | keys) - $timing_req | length) == 0 and
  (($timing_req - (.timing | keys)) | length) == 0 and
  ((.node | keys) - $node_req | length) == 0 and
  (($node_req - (.node | keys)) | length) == 0 and
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
