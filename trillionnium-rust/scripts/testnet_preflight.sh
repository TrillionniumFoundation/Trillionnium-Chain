#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="$ROOT/run/preflight"
LOG="$OUT_DIR/preflight-$TS.log"
SUMMARY="$OUT_DIR/go-no-go-$TS.txt"
mkdir -p "$OUT_DIR"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

log "start testnet preflight"

log "check rust toolchain"
command -v cargo >/dev/null
cargo --version | tee -a "$LOG"

log "check configs"
for f in configs/node1.toml configs/node2.toml configs/node3.toml; do
  [[ -f "$f" ]] || { echo "missing $f" | tee -a "$LOG"; exit 1; }
done

log "workspace tests"
cargo test --workspace | tee -a "$LOG"

log "single-node parallel sanity"
cargo run -q -p trnm-node -- \
  --config configs/node1.toml \
  --block-ms 5 \
  --max-blocks 6 \
  --demo-tasks 8 \
  --demo-keys 3 \
  --parallel-workers 4 | tee "$ROOT/run/parallel-sanity.log" | tee -a "$LOG"

if grep -E '\[tx\] apply_error|rollback=true' "$ROOT/run/parallel-sanity.log" >/dev/null; then
  log "parallel sanity failed: apply_error/rollback detected"
  exit 2
fi

if ! grep -q '^\[consensus\] finality_p50_ms=' "$ROOT/run/parallel-sanity.log"; then
  log "parallel sanity failed: missing consensus finality/recovery metrics"
  exit 3
fi

log "devnet + audit"
./scripts/devnet_up.sh | tee -a "$LOG"
sleep 12
./scripts/devnet_down.sh | tee -a "$LOG" || true
./scripts/audit_state_roots.sh | tee -a "$LOG"

latest_audit=$(ls -1dt run/audit/state-root-audit-*.txt | head -n 1)
grep -q 'summary ok=true mismatch=0 missing=0' "$latest_audit"
log "audit pass: $latest_audit"

log "quick benchmark matrix"
TXS=5000 ./scripts/run_bench_matrix.sh | tee -a "$LOG"
TXS=5000 ./scripts/run_bench_mixed_matrix.sh | tee -a "$LOG"
./scripts/executor_profile_report.py | tee -a "$LOG"

latest_bench=$(ls -1dt run/bench/bench-matrix-*.txt | head -n 1)
latest_mixed=$(ls -1dt run/bench/bench-mixed-matrix-*.txt | head -n 1)
latest_profile=$(ls -1dt run/bench/executor-profile-summary-*.txt | head -n 1)

cat > "$SUMMARY" <<EOF
rust_l1_testnet_preflight
status=GO
timestamp=$TS
log=$LOG
audit=$latest_audit
bench_classic=$latest_bench
bench_mixed=$latest_mixed
executor_profile=$latest_profile
EOF

cp -f "$SUMMARY" "$OUT_DIR/go-no-go-latest.txt"
cp -f "$LOG" "$OUT_DIR/preflight-latest.log"

log "[OK] testnet preflight passed"
log "summary: $SUMMARY"
echo "$LOG"