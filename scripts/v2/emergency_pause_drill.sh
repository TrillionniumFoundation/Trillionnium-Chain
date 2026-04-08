#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

OUT_DIR="${OUT_DIR:-$ROOT/run/health}"
OUT="$OUT_DIR/emergency-pause-drill-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p "$OUT_DIR"

# 1) baseline with pause=false should not emit rejected_by_pause
cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 --max-blocks 4 --demo-tasks 4 --demo-keys 2 --parallel-workers 4 > /tmp/trnm-node-baseline.log
if grep -q 'rejected_by_pause' /tmp/trnm-node-baseline.log; then
  echo "FAIL: baseline unexpectedly rejected by pause" | tee "$OUT"
  exit 1
fi

echo "baseline=pass" | tee "$OUT"

# 2) direct state drill: checked-path pause must be immediate and non-cancellable.
cargo test -q -p trnm-state tests::emergency_pause_checked_path_is_immediate_and_non_cancellable

echo "state_pause_checked_path=pass" | tee -a "$OUT"

# 3) governance param whitelist includes emergency_pause
cargo test -q -p trnm-state tests::governance_param_whitelist_enforced

echo "pause_param_whitelist=pass" | tee -a "$OUT"

# 4) node-level boolean gate formula must remain exact (paused => reject iff high risk)
cargo test -q -p trnm-node tests::emergency_pause_rejection_formula_is_exact_boolean_gate

echo "node_pause_formula=pass" | tee -a "$OUT"

echo "status=PASS" | tee -a "$OUT"
echo "[OK] emergency pause drill: $OUT"
