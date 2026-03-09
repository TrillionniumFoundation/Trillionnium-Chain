#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
# stabilize log/render ordering across environments for deterministic replay evidence
export TZ="${TZ:-UTC}"
export LC_ALL="${LC_ALL:-C}"
export LANG="${LANG:-$LC_ALL}"
export NO_COLOR="${NO_COLOR:-1}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"
export RUST_LOG_STYLE="${RUST_LOG_STYLE:-never}"
# avoid host-specific incremental cache effects in flaky CI checks
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
# keep any Python-backed helper output (if invoked transitively) hash-stable
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
# keep panic output stable across local/CI runs for replay diffing
export RUST_BACKTRACE="${RUST_BACKTRACE:-0}"
# normalize build metadata timestamps to improve replay artifact diffs
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"
umask "${UMASK:-022}"

RUNS="${RUNS:-5}"
RUN_TIMEOUT_SEC="${RUN_TIMEOUT_SEC:-120}"
if ! [[ "$RUNS" =~ ^[0-9]+$ ]] || [[ "$RUNS" -lt 1 ]]; then
  echo "RUNS must be a positive integer (got: $RUNS)" >&2
  exit 64
fi
if ! [[ "$RUN_TIMEOUT_SEC" =~ ^[0-9]+$ ]] || [[ "$RUN_TIMEOUT_SEC" -lt 1 ]]; then
  echo "RUN_TIMEOUT_SEC must be a positive integer (got: $RUN_TIMEOUT_SEC)" >&2
  exit 64
fi
TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN="gtimeout"
fi

# In CI, require an external timeout guard to avoid non-deterministic hangs.
# Keep this before any run directory setup so guard failures stay deterministic
# even under intentionally minimal PATH sandboxing.
if [[ -n "${CI:-}" && -z "$TIMEOUT_BIN" ]]; then
  echo "timeout binary not found (need timeout or gtimeout)" >&2
  exit 69
fi

RUN_TAG="${RUN_TAG:-$(date +%Y%m%d-%H%M%S)-$$}"
RUN_DIR="run/parallel-sanity-flaky-${RUN_TAG}"
mkdir -p "$RUN_DIR"

CMD=(
  cargo run --locked -q -p trnm-node --
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
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
export TZ="${TZ:-UTC}"
export LC_ALL="${LC_ALL:-C}"
export LANG="${LANG:-$LC_ALL}"
export NO_COLOR="${NO_COLOR:-1}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"
export RUST_LOG_STYLE="${RUST_LOG_STYLE:-never}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-0}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"
umask "${UMASK:-022}"
TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN="gtimeout"
fi
RUN_TIMEOUT_SEC="${RUN_TIMEOUT_SEC:-120}"
if ! [[ "$RUN_TIMEOUT_SEC" =~ ^[0-9]+$ ]] || [[ "$RUN_TIMEOUT_SEC" -lt 1 ]]; then
  echo "RUN_TIMEOUT_SEC must be a positive integer (got: $RUN_TIMEOUT_SEC)" >&2
  exit 64
fi
if [[ "$#" -gt 0 ]]; then
  "$@"
else
  if [[ -n "$TIMEOUT_BIN" ]]; then
    "$TIMEOUT_BIN" "$RUN_TIMEOUT_SEC" cargo run --locked -q -p trnm-node -- \
      --config configs/node1.toml \
      --block-ms 1 \
      --max-blocks 3 \
      --demo-tasks 2 \
      --demo-keys 2 \
      --parallel-workers 4
  else
    cargo run --locked -q -p trnm-node -- \
      --config configs/node1.toml \
      --block-ms 1 \
      --max-blocks 3 \
      --demo-tasks 2 \
      --demo-keys 2 \
      --parallel-workers 4
  fi
fi
EOF
chmod +x "$RUN_DIR/replay.sh"

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
