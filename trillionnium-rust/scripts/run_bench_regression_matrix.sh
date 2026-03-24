#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

OUT_DIR="${OUT_DIR:-$ROOT/run/bench}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT_DIR}/bench-regression-matrix-${TS}.csv"
mkdir -p "$OUT_DIR"

WORKLOADS=(classic mixed hot-streak)
STRATEGIES=(original aggressive-greedy)

# Backward-compatible defaults
TXS_DEFAULT="${TXS:-20000}"
TXS_LIST_STR="${TXS_LIST:-$TXS_DEFAULT}"
KEYS_LIST_STR="${KEYS_LIST:-2000 1000 500 200 100}"

# Optional preset for P2.3.1 high-variance sampling
if [ "${HIGH_VARIANCE_PRESET:-0}" = "1" ]; then
  TXS_LIST_STR="${TXS_LIST:-10000 20000 40000}"
  KEYS_LIST_STR="${KEYS_LIST:-64 128 256 512 1024 4096}"
fi

read -r -a TXS_LIST <<< "$TXS_LIST_STR"
read -r -a KEYS_LIST <<< "$KEYS_LIST_STR"

READ_FANOUT="${READ_FANOUT:-3}"
WRITE_EVERY="${WRITE_EVERY:-2}"

# Label the result source to avoid mixing default-path and experiment-path numbers.
if [ -n "${STRATEGY_SOURCE:-}" ]; then
  STRATEGY_SOURCE_VAL="$STRATEGY_SOURCE"
elif [ "${TRNM_AGGR_DEEP_SCAN:-0}" = "1" ] || [ -n "${TRNM_AGGR_SCAN_WINDOW:-}" ]; then
  STRATEGY_SOURCE_VAL="experiment"
else
  STRATEGY_SOURCE_VAL="default"
fi

printf "workload,txs,keys,strategy,strategy_source,groups,elapsed_ms,candidate_groups_scanned,stage_ww_checks,stage_ww_hits,stage_wr_checks,stage_wr_hits,stage_rw_checks,stage_rw_hits\n" > "$OUT"

run_case() {
  local workload="$1"
  local txs="$2"
  local keys="$3"
  local strategy="$4"
  local raw

  if [ "$workload" = "classic" ]; then
    raw=$(cargo run -q -p trnm-bench -- \
      --workload "$workload" \
      --txs "$txs" \
      --keys "$keys" \
      --strategy "$strategy" \
      --profile)
  else
    raw=$(cargo run -q -p trnm-bench -- \
      --workload "$workload" \
      --txs "$txs" \
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
    echo "failed to parse bench output for workload=$workload txs=$txs keys=$keys strategy=$strategy" >&2
    printf "%s\n" "$raw" >&2
    exit 21
  fi

  printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
    "$workload" "$txs" "$keys" "$strategy" "$STRATEGY_SOURCE_VAL" "$groups" "$elapsed" \
    "${candidate:-0}" "${stage_ww_checks:-0}" "${stage_ww_hits:-0}" \
    "${stage_wr_checks:-0}" "${stage_wr_hits:-0}" "${stage_rw_checks:-0}" "${stage_rw_hits:-0}" >> "$OUT"
}

echo "[bench-regression] txs=${TXS_LIST[*]} keys=${KEYS_LIST[*]} workloads=${WORKLOADS[*]} strategies=${STRATEGIES[*]}"
for workload in "${WORKLOADS[@]}"; do
  for txs in "${TXS_LIST[@]}"; do
    for keys in "${KEYS_LIST[@]}"; do
      for strategy in "${STRATEGIES[@]}"; do
        echo "  -> workload=$workload txs=$txs keys=$keys strategy=$strategy"
        run_case "$workload" "$txs" "$keys" "$strategy"
      done
    done
  done
done

echo "[OK] regression matrix CSV: $OUT"
