#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

RUNS="${RUNS:-5}"
mkdir -p run

ok=0
for i in $(seq 1 "$RUNS"); do
  log="run/parallel-sanity-flaky-${i}.log"
  cargo run -q -p trnm-node -- \
    --config configs/node1.toml \
    --block-ms 1 \
    --max-blocks 3 \
    --demo-tasks 2 \
    --demo-keys 2 \
    --parallel-workers 4 > "$log"

  if grep -E '\[tx\] apply_error|rollback=true' "$log" >/dev/null; then
    echo "flaky check failed at run=$i log=$log" >&2
    exit 2
  fi
  ok=$((ok+1))
done

echo "[OK] parallel flaky streak=${ok}/${RUNS}"
