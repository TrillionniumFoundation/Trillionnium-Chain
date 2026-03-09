#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/trillionnium-rust/scripts/check_parallel_flaky.sh"

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
  'umask "${UMASK:-022}"'
)

for line in "${required_lines[@]}"; do
  count=$(grep -Fxc -- "$line" "$SCRIPT" || true)
  if [[ "$count" -lt 2 ]]; then
    echo "[FAIL] expected guard line in both runner and replay template: $line" >&2
    exit 1
  fi
done

echo "[PASS] check_parallel_flaky replay script preserves deterministic env + rustup PATH guards"
