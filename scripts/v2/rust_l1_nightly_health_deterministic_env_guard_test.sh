#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/rust-l1-nightly-health.yml"

if [[ ! -f "$WF" ]]; then
  echo "[FAIL] missing workflow: $WF" >&2
  exit 1
fi

required_lines=(
  'TZ: UTC'
  'LANG: C.UTF-8'
  'LC_ALL: C.UTF-8'
  'LC_NUMERIC: C'
  'LC_COLLATE: C'
  'LC_TIME: C'
  'LC_CTYPE: C'
  'LC_MESSAGES: C'
  'LC_MONETARY: C'
  'LC_MEASUREMENT: C'
  'PYTHONHASHSEED: "0"'
  'PYTHONDONTWRITEBYTECODE: "1"'
  'PYTHONUTF8: "1"'
  'PYTHONIOENCODING: "UTF-8"' 
  'CI: "true"'
  'SOURCE_DATE_EPOCH: "1704067200"'
  'timeout-minutes: 180'
  'export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$WF"; then
    echo "[FAIL] missing deterministic nightly-health guard: $line" >&2
    exit 1
  fi
done

echo "[PASS] rust-l1-nightly-health keeps deterministic env + timeout guards"
