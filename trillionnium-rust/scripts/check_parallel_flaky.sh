#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

RUNS="${RUNS:-5}"
RUN_TIMEOUT_SEC="${RUN_TIMEOUT_SEC:-120}"
mkdir -p run

TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN="gtimeout"
fi

ok=0
for i in $(seq 1 "$RUNS"); do
  log="run/parallel-sanity-flaky-${i}.log"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    if ! "$TIMEOUT_BIN" "$RUN_TIMEOUT_SEC" \
      cargo run -q -p trnm-node -- \
      --config configs/node1.toml \
      --block-ms 1 \
      --max-blocks 3 \
      --demo-tasks 2 \
      --demo-keys 2 \
      --parallel-workers 4 > "$log"; then
      rc=$?
      if [[ "$rc" -eq 124 ]]; then
        echo "flaky check timed out at run=$i after ${RUN_TIMEOUT_SEC}s log=$log" >&2
      fi
      exit "$rc"
    fi
  else
    cargo run -q -p trnm-node -- \
      --config configs/node1.toml \
      --block-ms 1 \
      --max-blocks 3 \
      --demo-tasks 2 \
      --demo-keys 2 \
      --parallel-workers 4 > "$log"
  fi

  if grep -E '\[tx\] apply_error|rollback=true' "$log" >/dev/null; then
    echo "flaky check failed at run=$i log=$log" >&2
    exit 2
  fi
  ok=$((ok+1))
done

echo "[OK] parallel flaky streak=${ok}/${RUNS}"
