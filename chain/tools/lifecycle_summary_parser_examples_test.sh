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

extract_finalize_tx='(.phase_txs.finalize_unbonding // .tx_finalize_unbonding // .last_tx // "")'
extract_release_height='(.timing.release_height // .release_height // 0)'
extract_node_height='(.node.height // .node_height // "")'

[[ "$(jq -r "$extract_finalize_tx" "$v1_fail")" == "txfin" ]]
[[ "$(jq -r "$extract_finalize_tx" "$v2_ok")" == "txfin" ]]
[[ "$(jq -r "$extract_finalize_tx" "$v3_ok")" == "txfin" ]]

[[ "$(jq -r "$extract_release_height" "$v2_ok")" == "103" ]]
[[ "$(jq -r "$extract_release_height" "$v3_ok")" == "103" ]]

[[ "$(jq -r "$extract_node_height" "$v2_ok")" == "110" ]]
[[ "$(jq -r "$extract_node_height" "$v3_ok")" == "110" ]]

jq -e '.schema_version == 1 and .status == "failed" and (.reason | startswith("finalize-unbonding broadcast failed"))' "$v1_fail" >/dev/null
jq -e '.schema_version == 2 and .status == "ok" and has("phase_txs") | not' "$v2_ok" >/dev/null
jq -e '.schema_version == 3 and .status == "ok" and .phase_txs.finalize_unbonding == "txfin" and .timing.release_height == 103' "$v3_ok" >/dev/null

echo "PASS: lifecycle summary parser examples"
