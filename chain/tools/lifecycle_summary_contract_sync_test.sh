#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONTRACT_MD="$ROOT_DIR/tools/LIFECYCLE_SUMMARY_SCHEMA_CONTRACT.md"
CONTRACT_JSON="$ROOT_DIR/tools/lifecycle_summary_schema_contract.json"

command -v jq >/dev/null 2>&1 || {
	echo "[ERR] jq not found in PATH" >&2
	exit 1
}

extract_backtick_tokens() {
	local from_marker="$1"
	local to_marker="$2"
	awk -v from="$from_marker" -v to="$to_marker" '
		$0 == from {in_block=1; next}
		$0 == to {in_block=0}
		in_block && $0 ~ /^[[:space:]]*-[[:space:]]/ {print}
	' "$CONTRACT_MD" | grep -o '`[^`]*`' | tr -d '`' || true
}

v2_doc_tokens="$({
	extract_backtick_tokens 'Required top-level fields (same as v1):' '## v3 Contract'
} | sort -u)"

v2_expected_tokens="$(jq -r '.flat_required[]' "$CONTRACT_JSON" | sort -u)"

if [[ "$v2_doc_tokens" != "$v2_expected_tokens" ]]; then
	echo "[ERR] v2 contract markdown fields drift from lifecycle_summary_schema_contract.json" >&2
	echo "--- markdown(v2) ---" >&2
	echo "$v2_doc_tokens" >&2
	echo "--- json(flat_required) ---" >&2
	echo "$v2_expected_tokens" >&2
	exit 1
fi

v3_doc_tokens="$({
	extract_backtick_tokens '## v3 Contract' '### Status Semantics'
} | sort -u)"

v3_expected_tokens="$(jq -r '(.v3_nested | keys[]) as $k | $k, (.v3_nested[$k][] )' "$CONTRACT_JSON" | sort -u)"

if [[ "$v3_doc_tokens" != "$v3_expected_tokens" ]]; then
	echo "[ERR] v3 contract markdown nested fields drift from lifecycle_summary_schema_contract.json" >&2
	echo "--- markdown(v3 nested) ---" >&2
	echo "$v3_doc_tokens" >&2
	echo "--- json(v3_nested) ---" >&2
	echo "$v3_expected_tokens" >&2
	exit 1
fi

echo "PASS: lifecycle summary schema contract markdown/json synchronized"
