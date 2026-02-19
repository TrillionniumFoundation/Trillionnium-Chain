#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/build/chaind}"
HOME_DIR="${HOME_DIR:-/Users/qianqi/.chain}"
NODE="${NODE:-tcp://127.0.0.1:26657}"
OUT_DIR="${OUT_DIR:-$ROOT/data/observability/legacy-submit}"
DATE_TAG="${DATE_TAG:-$(date +%F)}"
LIMIT="${LIMIT:-100}"
MAX_PAGES="${MAX_PAGES:-50}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1"; exit 1; }; }
need jq

if [[ ! -x "$BIN" ]]; then
  echo "[ERR] chaind not executable: $BIN"
  exit 1
fi

mkdir -p "$OUT_DIR"
OUT_FILE="$OUT_DIR/$DATE_TAG.txt"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

accepted=0
rejected=0
total=0
workers_file="$TMP_DIR/workers.txt"
: > "$workers_file"

count_reason() {
  local reason="$1"
  grep -c "^$reason$" "$TMP_DIR/reasons.txt" 2>/dev/null || true
}

: > "$TMP_DIR/reasons.txt"

for page in $(seq 1 "$MAX_PAGES"); do
  set +e
  "$BIN" query txs \
    --query "workload_legacy_submit_observe.result EXISTS" \
    --node "$NODE" --home "$HOME_DIR" \
    --page "$page" --limit "$LIMIT" --order_by dsc -o json \
    > "$TMP_DIR/page-$page.json" 2>"$TMP_DIR/page-$page.err"
  rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    if [[ "$page" -eq 1 ]]; then
      echo "[ERR] tx query failed:"
      cat "$TMP_DIR/page-$page.err"
      exit 1
    fi
    break
  fi

  tx_count="$(jq '.txs | length' "$TMP_DIR/page-$page.json" 2>/dev/null || echo 0)"
  if [[ "$tx_count" -eq 0 ]]; then
    break
  fi

  while IFS=$'\t' read -r res reason worker; do
    [[ -z "$res" ]] && continue
    total=$((total+1))
    [[ "$res" == "accepted" ]] && accepted=$((accepted+1))
    [[ "$res" == "rejected" ]] && rejected=$((rejected+1))
    [[ -n "$reason" ]] && echo "$reason" >> "$TMP_DIR/reasons.txt"
    [[ -n "$worker" ]] && echo "$worker" >> "$workers_file"
  done < <(
    jq -r '
      .txs[]? as $tx |
      ($tx.tx_result.events // [])[]? |
      select(.type == "workload_legacy_submit_observe") |
      {
        result: ((.attributes[]? | select(.key=="result") | .value) // ""),
        reason: ((.attributes[]? | select(.key=="reason") | .value) // ""),
        worker: ((.attributes[]? | select(.key=="worker") | .value) // "")
      } |
      "\(.result)\t\(.reason)\t\(.worker)"
    ' "$TMP_DIR/page-$page.json"
  )

done

distinct_workers=0
if [[ -s "$workers_file" ]]; then
  distinct_workers="$(sort -u "$workers_file" | wc -l | tr -d ' ')"
fi

legacy_disabled="$(count_reason legacy_disabled)"
invalid_state_transition="$(count_reason invalid_state_transition)"
unauthorized_worker="$(count_reason unauthorized_worker)"
other=$(( rejected - legacy_disabled - invalid_state_transition - unauthorized_worker ))
if (( other < 0 )); then other=0; fi

cat > "$OUT_FILE" <<EOF
Date: $DATE_TAG
Env: local
Window: tx-search(workload_legacy_submit_observe.result EXISTS)

legacy_submit_total: $total
legacy_submit_accepted: $accepted
legacy_submit_rejected: $rejected
rejected_breakdown:
  - legacy_disabled: $legacy_disabled
  - invalid_state_transition: $invalid_state_transition
  - unauthorized_worker: $unauthorized_worker
  - other: $other
distinct_workers_legacy_submit: $distinct_workers

Decision hint:
- If total==0 for >=14 days in all target envs, P3 delete gate can be opened.
EOF

echo "Wrote: $OUT_FILE"