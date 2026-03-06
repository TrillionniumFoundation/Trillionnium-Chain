#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

RUNS="${RUNS:-5}"
RUN_TIMEOUT_SEC="${RUN_TIMEOUT_SEC:-120}"
RUN_TAG="${RUN_TAG:-$(date +%Y%m%d-%H%M%S)-$$}"
RUN_DIR="run/parallel-sanity-flaky-${RUN_TAG}"
mkdir -p "$RUN_DIR"

CMD=(
  cargo run -q -p trnm-node --
  --config configs/node1.toml
  --block-ms 1
  --max-blocks 3
  --demo-tasks 2
  --demo-keys 2
  --parallel-workers 4
)

cat >"$RUN_DIR/replay.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$ROOT"
if [[ "$#" -gt 0 ]]; then
  "$@"
else
  cargo run -q -p trnm-node -- \
    --config configs/node1.toml \
    --block-ms 1 \
    --max-blocks 3 \
    --demo-tasks 2 \
    --demo-keys 2 \
    --parallel-workers 4
fi
EOF
chmod +x "$RUN_DIR/replay.sh"

TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN="gtimeout"
fi

ok=0
for i in $(seq 1 "$RUNS"); do
  log="$RUN_DIR/run-${i}.log"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    if "$TIMEOUT_BIN" "$RUN_TIMEOUT_SEC" "${CMD[@]}" > "$log"; then
      :
    else
      rc=$?
      if [[ "$rc" -eq 124 ]]; then
        echo "flaky check timed out at run=$i after ${RUN_TIMEOUT_SEC}s log=$log" >&2
      fi
      exit "$rc"
    fi
  else
    "${CMD[@]}" > "$log"
  fi

  if grep -E '\[tx\] apply_error|rollback=true' "$log" >/dev/null; then
    echo "flaky check failed at run=$i log=$log" >&2
    exit 2
  fi
  ok=$((ok+1))
done

echo "[OK] parallel flaky streak=${ok}/${RUNS} run_dir=${RUN_DIR}"
