#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TXS="${TXS:-20000}"
OUT_DIR="${OUT_DIR:-$ROOT/run/bench}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT_DIR}/bench-regression-matrix-${TS}.csv"
mkdir -p "$OUT_DIR"

WORKLOADS=(classic mixed hot-streak)
STRATEGIES=(original aggressive-greedy)
KEYS_LIST=(2000 1000 500 200 100)
READ_FANOUT="${READ_FANOUT:-3}"
WRITE_EVERY="${WRITE_EVERY:-2}"

printf "workload,txs,keys,strategy,groups,elapsed_ms,candidate_groups_scanned,stage_ww_checks,stage_ww_hits,stage_wr_checks,stage_wr_hits,stage_rw_checks,stage_rw_hits\n" > "$OUT"

run_case() {
  local workload="$1"
  local keys="$2"
  local strategy="$3"
  local raw

  if [ "$workload" = "classic" ]; then
    raw=$(cargo run -q -p trnm-bench -- \
      --workload "$workload" \
      --txs "$TXS" \
      --keys "$keys" \
      --strategy "$strategy" \
      --profile)
  else
    raw=$(cargo run -q -p trnm-bench -- \
      --workload "$workload" \
      --txs "$TXS" \
      --keys "$keys" \
      --read-fanout "$READ_FANOUT" \
      --write-every "$WRITE_EVERY" \
      --strategy "$strategy" \
      --profile)
  fi

  local groups elapsed candidate stage_ww_checks stage_ww_hits stage_wr_checks stage_wr_hits stage_rw_checks stage_rw_hits
  groups=$(printf "%s\n" "$raw" | awk -F= '/^groups=/{print $2; exit}')
  elapsed=$(printf "%s\n" "$raw" | awk -F= '/^elapsed_ms=/{print $2; exit}')
  candidate=$(printf "%s\n" "$raw" | awk -F= '/^profile.candidate_groups_scanned=/{print $2; exit}')
  stage_ww_checks=$(printf "%s\n" "$raw" | awk -F= '/^profile.stage_ww_checks=/{print $2; exit}')
  stage_ww_hits=$(printf "%s\n" "$raw" | awk -F= '/^profile.stage_ww_hits=/{print $2; exit}')
  stage_wr_checks=$(printf "%s\n" "$raw" | awk -F= '/^profile.stage_wr_checks=/{print $2; exit}')
  stage_wr_hits=$(printf "%s\n" "$raw" | awk -F= '/^profile.stage_wr_hits=/{print $2; exit}')
  stage_rw_checks=$(printf "%s\n" "$raw" | awk -F= '/^profile.stage_rw_checks=/{print $2; exit}')
  stage_rw_hits=$(printf "%s\n" "$raw" | awk -F= '/^profile.stage_rw_hits=/{print $2; exit}')

  if [ -z "$groups" ] || [ -z "$elapsed" ]; then
    echo "failed to parse bench output for workload=$workload keys=$keys strategy=$strategy" >&2
    printf "%s\n" "$raw" >&2
    exit 21
  fi

  printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
    "$workload" "$TXS" "$keys" "$strategy" "$groups" "$elapsed" \
    "${candidate:-0}" "${stage_ww_checks:-0}" "${stage_ww_hits:-0}" \
    "${stage_wr_checks:-0}" "${stage_wr_hits:-0}" "${stage_rw_checks:-0}" "${stage_rw_hits:-0}" >> "$OUT"
}

echo "[bench-regression] txs=$TXS keys=${KEYS_LIST[*]} workloads=${WORKLOADS[*]} strategies=${STRATEGIES[*]}"
for workload in "${WORKLOADS[@]}"; do
  for keys in "${KEYS_LIST[@]}"; do
    for strategy in "${STRATEGIES[@]}"; do
      echo "  -> workload=$workload keys=$keys strategy=$strategy"
      run_case "$workload" "$keys" "$strategy"
    done
  done
done

echo "[OK] regression matrix CSV: $OUT"
