#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

OUT_DIR="$ROOT/run"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"

pids=()
for n in 1 2 3 4; do
  log="$OUT_DIR/bft4-node${n}-${TS}.log"
  cargo run -q -p trnm-node -- \
    --config "configs/node${n}.toml" \
    --block-ms 5 \
    --max-blocks 4 \
    --demo-tasks 6 \
    --demo-keys 3 \
    --parallel-workers 4 \
    --validators 4 \
    --byzantine 1 \
    --bft-max-rounds 3 \
    --bft-fault-rounds 1 >"$log" 2>&1 &
  pids+=("$!")
done

for p in "${pids[@]}"; do
  wait "$p"
done

for n in 1 2 3 4; do
  log="$OUT_DIR/bft4-node${n}-${TS}.log"
  grep -q '^\[bft\].*step=Commit' "$log"
  grep -q '^\[consensus\].*bft_committed_heights=' "$log"
  grep -q '^\[bft-slash\] event=double_vote' "$log"
  if grep -E '\[tx\] apply_error|rollback=true' "$log" >/dev/null; then
    echo "[FAIL] apply_error/rollback found: $log" >&2
    exit 2
  fi
done

report="$OUT_DIR/bft4-smoke-${TS}.txt"
{
  echo "bft4_smoke_ts=$TS"
  for n in 1 2 3 4; do
    log="$OUT_DIR/bft4-node${n}-${TS}.log"
    c=$(grep -c '^\[bft\].*step=Commit' "$log" || true)
    echo "node${n}_commit_events=$c log=$log"
  done
  echo "status=PASS"
} > "$report"

echo "[OK] bft 4-node smoke passed: $report"
