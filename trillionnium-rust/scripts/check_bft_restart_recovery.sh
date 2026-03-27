#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

RUNS="${RUNS:-5}"
OUT_DIR="$ROOT/run"
TS="$(date +%Y%m%d-%H%M%S)"
REPORT="$OUT_DIR/bft-restart-recovery-$TS.txt"
WAL_DIR="$OUT_DIR/consensus-wal-restart-$TS"
mkdir -p "$OUT_DIR" "$WAL_DIR"

pass=0
for i in $(seq 1 "$RUNS"); do
  pre="$OUT_DIR/bft-restart-pre-${TS}-${i}.log"
  post="$OUT_DIR/bft-restart-post-${TS}-${i}.log"

  wal_file="$WAL_DIR/consensus-wal.toml"
  rm -f "$wal_file"

  cargo run -q -p trnm-node -- \
    --config configs/node1.toml \
    --block-ms 30 \
    --max-blocks 50 \
    --demo-tasks 12 \
    --demo-keys 3 \
    --validators 4 \
    --byzantine 1 \
    --bft-max-rounds 3 \
    --bft-fault-rounds 1 \
    --bft-wal-dir "$WAL_DIR" >"$pre" 2>&1 &
  pid=$!

  for _ in $(seq 1 40); do
    [[ -f "$wal_file" ]] && break
    sleep 0.05
  done
  kill -9 "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true

  if [[ ! -f "$wal_file" ]]; then
    echo "[FAIL] restart recovery did not produce WAL run=$i wal=$wal_file pre=$pre" >&2
    exit 3
  fi

  cargo run -q -p trnm-node -- \
    --config configs/node1.toml \
    --block-ms 5 \
    --max-blocks 3 \
    --demo-tasks 6 \
    --demo-keys 3 \
    --validators 4 \
    --byzantine 1 \
    --bft-max-rounds 3 \
    --bft-fault-rounds 1 \
    --bft-wal-dir "$WAL_DIR" >"$post" 2>&1

  grep -q '^\[bft-recover\] restored height=' "$post"
  grep -q '^\[bft\].*step=Commit' "$post"
  if grep -E '\[tx\] apply_error|rollback=true' "$post" >/dev/null; then
    echo "[FAIL] recovery apply_error/rollback run=$i log=$post" >&2
    exit 2
  fi
  pass=$((pass+1))
done

{
  echo "runs=$RUNS"
  echo "pass=$pass"
  echo "wal_dir=$WAL_DIR"
  echo "status=PASS"
} > "$REPORT"

echo "[OK] bft restart recovery passed: $REPORT"
