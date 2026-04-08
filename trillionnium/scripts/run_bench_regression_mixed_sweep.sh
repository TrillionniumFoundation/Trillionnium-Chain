#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

OUT_DIR="${OUT_DIR:-$ROOT/run/bench}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT_DIR}/bench-regression-mixed-sweep-${TS}.csv"
mkdir -p "$OUT_DIR"

TXS_LIST_STR="${TXS_LIST:-10000}"
KEYS_LIST_STR="${KEYS_LIST:-256 1024}"
READ_FANOUT_LIST_STR="${READ_FANOUT_LIST:-2 4 8}"
WRITE_EVERY_LIST_STR="${WRITE_EVERY_LIST:-1 2 4}"
STRATEGIES=(original aggressive-greedy)

read -r -a TXS_LIST <<< "$TXS_LIST_STR"
read -r -a KEYS_LIST <<< "$KEYS_LIST_STR"
read -r -a READ_FANOUT_LIST <<< "$READ_FANOUT_LIST_STR"
read -r -a WRITE_EVERY_LIST <<< "$WRITE_EVERY_LIST_STR"

printf "workload,txs,keys,read_fanout,write_every,strategy,groups,elapsed_ms,candidate_groups_scanned,stage_ww_checks,stage_ww_hits,stage_wr_checks,stage_wr_hits,stage_rw_checks,stage_rw_hits\n" > "$OUT"

run_case() {
  local txs="$1"
  local keys="$2"
  local rf="$3"
  local we="$4"
  local strategy="$5"

  local raw
  raw=$(cargo run -q -p trnm-bench -- \
    --workload mixed \
    --txs "$txs" \
    --keys "$keys" \
    --read-fanout "$rf" \
    --write-every "$we" \
    --strategy "$strategy" \
    --profile)

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
    echo "failed to parse mixed sweep output txs=$txs keys=$keys rf=$rf we=$we strategy=$strategy" >&2
    printf "%s\n" "$raw" >&2
    exit 31
  fi

  printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
    "mixed" "$txs" "$keys" "$rf" "$we" "$strategy" "$groups" "$elapsed" \
    "${candidate:-0}" "${stage_ww_checks:-0}" "${stage_ww_hits:-0}" \
    "${stage_wr_checks:-0}" "${stage_wr_hits:-0}" "${stage_rw_checks:-0}" "${stage_rw_hits:-0}" >> "$OUT"
}

echo "[mixed-sweep] txs=${TXS_LIST[*]} keys=${KEYS_LIST[*]} rf=${READ_FANOUT_LIST[*]} we=${WRITE_EVERY_LIST[*]}"
for txs in "${TXS_LIST[@]}"; do
  for keys in "${KEYS_LIST[@]}"; do
    for rf in "${READ_FANOUT_LIST[@]}"; do
      for we in "${WRITE_EVERY_LIST[@]}"; do
        for strategy in "${STRATEGIES[@]}"; do
          echo "  -> txs=$txs keys=$keys rf=$rf we=$we strategy=$strategy"
          run_case "$txs" "$keys" "$rf" "$we" "$strategy"
        done
      done
    done
  done
done

echo "[OK] mixed sweep CSV: $OUT"
