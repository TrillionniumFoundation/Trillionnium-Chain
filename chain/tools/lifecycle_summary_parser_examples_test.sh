#!/usr/bin/env bash
set -euo pipefail

command -v jq >/dev/null 2>&1 || {
	echo "[ERR] jq not found in PATH" >&2
	exit 1
}

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
EXAMPLES_DIR="$ROOT_DIR/tools/examples"

v1_fail="$EXAMPLES_DIR/lifecycle_summary_v1_failed.json"
v2_ok="$EXAMPLES_DIR/lifecycle_summary_v2_ok.json"
v3_ok="$EXAMPLES_DIR/lifecycle_summary_v3_ok.json"

assert_eq() {
	local got="$1"
	local expected="$2"
	local label="$3"
	if [[ "$got" != "$expected" ]]; then
		echo "[ERR] assert_eq failed: $label expected=$expected got=$got" >&2
		exit 1
	fi
}

for f in "$v1_fail" "$v2_ok" "$v3_ok"; do
	[[ -f "$f" ]] || {
		echo "[ERR] fixture not found: $f" >&2
		exit 1
	}
	jq -e . "$f" >/dev/null
done

extract_finalize_tx='(([.phase_txs.finalize_unbonding, .tx_finalize_unbonding, .last_tx, ""] | map(select(. != null and . != "")) | .[0]) // "")'
extract_release_height='(.timing.release_height // .release_height // 0)'
extract_node_height='(.node.height // .node_height // "")'

assert_eq "$(jq -r "$extract_finalize_tx" "$v1_fail")" "txfin" "v1 finalize_tx fallback"
assert_eq "$(jq -r "$extract_finalize_tx" "$v2_ok")" "txfin" "v2 finalize_tx"
assert_eq "$(jq -r "$extract_finalize_tx" "$v3_ok")" "txfin" "v3 finalize_tx"

assert_eq "$(jq -r "$extract_release_height" "$v2_ok")" "103" "v2 release_height"
assert_eq "$(jq -r "$extract_release_height" "$v3_ok")" "103" "v3 release_height"

assert_eq "$(jq -r "$extract_node_height" "$v2_ok")" "110" "v2 node_height"
assert_eq "$(jq -r "$extract_node_height" "$v3_ok")" "110" "v3 node_height"

jq -e '.schema_version == 1 and .status == "failed" and (.reason | startswith("finalize-unbonding broadcast failed"))' "$v1_fail" >/dev/null
jq -e '.schema_version == 2 and .status == "ok" and (has("phase_txs") | not)' "$v2_ok" >/dev/null
jq -e '.schema_version == 3 and .status == "ok" and .phase_txs.finalize_unbonding == "txfin" and .timing.release_height == 103' "$v3_ok" >/dev/null

echo "PASS: lifecycle summary parser examples"
