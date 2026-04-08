#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/trillionnium/scripts/check_parallel_flaky.sh"

if [[ ! -f "$SCRIPT" ]]; then
  echo "[FAIL] missing script: $SCRIPT" >&2
  exit 1
fi

required_lines=(
  'export PATH="/opt/homebrew/opt/rustup/bin:$PATH"'
  'export TZ="${TZ:-UTC}"'
  'export LC_ALL="${LC_ALL:-C}"'
  'export LANG="${LANG:-$LC_ALL}"'
  'export NO_COLOR="${NO_COLOR:-1}"'
  'export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"'
  'export RUST_LOG_STYLE="${RUST_LOG_STYLE:-never}"'
  'export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"'
  'export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"'
  'export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"'
  'export RUST_BACKTRACE="${RUST_BACKTRACE:-0}"'
  'export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"'
  'umask "${UMASK:-022}"'
  'RUN_TIMEOUT_SEC="${RUN_TIMEOUT_SEC:-120}"'
  'RUN_TIMEOUT_SEC must be a positive integer (got:'
)

for line in "${required_lines[@]}"; do
  count=$(grep -Fc -- "$line" "$SCRIPT" || true)
  if [[ "$count" -lt 2 ]]; then
    echo "[FAIL] expected guard line in both runner and replay template: $line" >&2
    exit 1
  fi
done

echo "[PASS] check_parallel_flaky replay script preserves deterministic env + rustup PATH guards"
