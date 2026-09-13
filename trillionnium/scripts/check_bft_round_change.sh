#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export TZ="${TZ:-UTC}"
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"
export CARGO_INCREMENTAL="0"
export CARGO_TERM_COLOR="never"
export CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-true}"

OUT_DIR="$ROOT/run"
mkdir -p "$OUT_DIR"
TS="$(date -u +%Y%m%d-%H%M%S)"
LOG="$OUT_DIR/bft-round-change-${TS}.log"
REPORT="$OUT_DIR/bft-round-change-${TS}.txt"

cargo test -p trnm-consensus-sim --test scenarios --locked --offline \
  two_plus_two_partition_cannot_finalize_and_heal_restores_progress -- --exact --nocapture \
  2>&1 | tee "$LOG"

{
  echo "consensus=native-poco-bft"
  echo "test_surface=trnm-consensus-sim/scenarios:partition-heal"
  echo "legacy_harness=false"
  echo "log=$LOG"
  echo "status=PASS"
} > "$REPORT"

echo "[OK] native PoCO partition/heal round-progress scenario passed: $REPORT"
