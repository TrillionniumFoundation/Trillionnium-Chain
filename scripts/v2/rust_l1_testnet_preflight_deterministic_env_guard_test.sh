#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/rust-l1-testnet-preflight.yml"

if [[ ! -f "$WF" ]]; then
  echo "[FAIL] missing workflow: $WF" >&2
  exit 1
fi

required_lines=(
  'group: rust-l1-testnet-preflight-${{ github.ref }}'
  'cancel-in-progress: true'
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
  'LC_NAME: C'
  'LC_PAPER: C'
  'LC_ADDRESS: C'
  'LC_TELEPHONE: C'
  'PYTHONHASHSEED: "0"'
  'PYTHONDONTWRITEBYTECODE: "1"'
  'PYTHONIOENCODING: "UTF-8"'
  'PYTHONUTF8: "1"'
  'CI: "true"'
  'SOURCE_DATE_EPOCH: "1704067200"'
  'RUST_TEST_THREADS: "1"'
  'timeout-minutes: 120'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$WF"; then
    echo "[FAIL] missing deterministic testnet-preflight guard: $line" >&2
    exit 1
  fi
done

echo "[PASS] rust-l1-testnet-preflight keeps deterministic env + timeout guards"
