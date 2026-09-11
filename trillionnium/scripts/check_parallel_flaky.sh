#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export TZ="${TZ:-UTC}"
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"
export PYTHONHASHSEED="0"
export CARGO_INCREMENTAL="0"
export CARGO_TERM_COLOR="never"
export CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-true}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"

RUNS="${RUNS:-2}"
if ! [[ "$RUNS" =~ ^[0-9]+$ ]] || [[ "$RUNS" -lt 1 ]]; then
  echo "RUNS must be a positive integer (got: $RUNS)" >&2
  exit 64
fi

RUN_TAG="${RUN_TAG:-$(date -u +%Y%m%d-%H%M%S)-$$}"
RUN_DIR="run/parallel-sanity-flaky-${RUN_TAG}"
mkdir -p "$RUN_DIR"

for i in $(seq 1 "$RUNS"); do
  log="$RUN_DIR/run-${i}.log"
  {
    echo "run=$i"
    echo "consensus=native-poco-bft"
    echo "execution=deterministic-native-mvcc"
    cargo test -p trnm-native-execution-v0 --locked --offline
    cargo test -p trnm-poco-global-execution-v1 --locked --offline
  } 2>&1 | tee "$log"
done

MANIFEST="$RUN_DIR/manifest.txt"
{
  echo "streak=${RUNS}/${RUNS}"
  echo "consensus=native-poco-bft"
  echo "execution=deterministic-native-mvcc"
  echo "legacy_harness=false"
  echo "source=$(git rev-parse HEAD)"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$RUN_DIR"/run-*.log
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$RUN_DIR"/run-*.log
  fi
} > "$MANIFEST"

echo "[OK] native deterministic parallel execution streak=${RUNS}/${RUNS} run_dir=${RUN_DIR}"
