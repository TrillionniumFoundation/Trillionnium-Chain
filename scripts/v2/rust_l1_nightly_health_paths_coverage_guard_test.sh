#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/rust-l1-nightly-health.yml"

required_paths=(
  "trillionnium/**"
  "scripts/**"
  "config/alert-policy/**"
  ".github/workflows/rust-l1-nightly-health.yml"
)

for p in "${required_paths[@]}"; do
  if ! grep -Fq -- "- '$p'" "$WF"; then
    echo "[NIGHTLY-PATHS][FAIL] missing workflow trigger path: $p" >&2
    exit 1
  fi
done

echo "[NIGHTLY-PATHS][PASS] workflow trigger paths include required nightly health inputs"
