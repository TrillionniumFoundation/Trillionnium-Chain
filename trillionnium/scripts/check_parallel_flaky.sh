#!/usr/bin/env bash
set -euo pipefail

# Keep the runner and its replay artifact byte-for-byte deterministic across
# host images.  These assignments intentionally precede every external
# command: the CI guard below is tested with an intentionally empty PATH.
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
export TZ="${TZ:-UTC}"
export LC_ALL="${LC_ALL:-C}"
export LANG="${LANG:-$LC_ALL}"
export LC_NUMERIC="${LC_NUMERIC:-C}"
export LC_COLLATE="${LC_COLLATE:-C}"
export LC_TIME="${LC_TIME:-C}"
export NO_COLOR="${NO_COLOR:-1}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"
export RUST_LOG_STYLE="${RUST_LOG_STYLE:-never}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-0}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"
export CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-true}"
umask "${UMASK:-022}"

RUNS="${RUNS:-2}"
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

# In CI, require an external timeout guard before setup (including dirname,
# date, mkdir, and Cargo).  This keeps a missing runner prerequisite a stable
# contract failure rather than an incidental command-not-found exit.
if [[ -n "${CI:-}" && -z "$TIMEOUT_BIN" ]]; then
  echo "timeout binary not found (need timeout or gtimeout)" >&2
  exit 69
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUN_TAG="${RUN_TAG:-$(date -u +%Y%m%d-%H%M%S)-$$}"
RUN_DIR="run/parallel-sanity-flaky-${RUN_TAG}"
mkdir -p "$RUN_DIR"

run_with_timeout() {
  if [[ -n "$TIMEOUT_BIN" ]]; then
    "$TIMEOUT_BIN" "$RUN_TIMEOUT_SEC" "$@"
  else
    "$@"
  fi
}

# Keep a self-contained replay artifact.  The same guards are deliberately
# present in both copies so replaying under CI cannot silently lose the
# timeout boundary or accept malformed input.
cat >"$RUN_DIR/replay.sh" <<'REPLAY'
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
export TZ="${TZ:-UTC}"
export LC_ALL="${LC_ALL:-C}"
export LANG="${LANG:-$LC_ALL}"
export LC_NUMERIC="${LC_NUMERIC:-C}"
export LC_COLLATE="${LC_COLLATE:-C}"
export LC_TIME="${LC_TIME:-C}"
export NO_COLOR="${NO_COLOR:-1}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"
export RUST_LOG_STYLE="${RUST_LOG_STYLE:-never}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-0}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"
export CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-true}"
umask "${UMASK:-022}"

RUN_TIMEOUT_SEC="${RUN_TIMEOUT_SEC:-120}"
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
if [[ -n "${CI:-}" && -z "$TIMEOUT_BIN" ]]; then
  echo "timeout binary not found (need timeout or gtimeout)" >&2
  exit 69
fi

run_with_timeout() {
  if [[ -n "$TIMEOUT_BIN" ]]; then
    "$TIMEOUT_BIN" "$RUN_TIMEOUT_SEC" "$@"
  else
    "$@"
  fi
}

if [[ "$#" -gt 0 ]]; then
  run_with_timeout "$@"
else
  run_with_timeout cargo test -p trnm-native-execution-v0 --locked --offline
  run_with_timeout cargo test -p trnm-poco-global-execution-v1 --locked --offline
fi
REPLAY
chmod +x "$RUN_DIR/replay.sh"

for i in $(seq 1 "$RUNS"); do
  log="$RUN_DIR/run-${i}.log"
  {
    echo "run=$i"
    echo "consensus=native-poco-bft"
    echo "execution=deterministic-native-mvcc"
    run_with_timeout cargo test -p trnm-native-execution-v0 --locked --offline
    run_with_timeout cargo test -p trnm-poco-global-execution-v1 --locked --offline
  } 2>&1 | tee "$log"
done

MANIFEST="$RUN_DIR/manifest.txt"
{
  echo "streak=${RUNS}/${RUNS}"
  echo "run_timeout_sec=${RUN_TIMEOUT_SEC}"
  echo "consensus=native-poco-bft"
  echo "execution=deterministic-native-mvcc"
  echo "legacy_harness=false"
  echo "source=$(git rev-parse HEAD)"
  echo "replay=$RUN_DIR/replay.sh"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$RUN_DIR"/run-*.log
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$RUN_DIR"/run-*.log
  fi
} > "$MANIFEST"

echo "[OK] native deterministic parallel execution streak=${RUNS}/${RUNS} run_dir=${RUN_DIR}"
