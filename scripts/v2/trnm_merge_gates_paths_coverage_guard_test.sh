#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/trnm-merge-gates.yml"

required_paths=(
  "docs/**"
  "config/alert-policy/**"
  "trillionnium/**"
  "web4-frontend/**"
  "scripts/**"
  ".github/workflows/agent-user-phasea-gate.yml"
  ".github/workflows/p1-rust-sidecar.yml"
  ".github/workflows/rust-l1-nightly-health.yml"
  ".github/workflows/rust-l1-testnet-preflight.yml"
  ".github/workflows/trnm-gate-quick-check.yml"
  ".github/workflows/trnm-merge-gates.yml"
  ".github/workflows/web4-frontend-ci.yml"
)

for p in "${required_paths[@]}"; do
  count=$(grep -Fc -- "- '$p'" "$WF" || true)
  if [[ "$count" -lt 2 ]]; then
    echo "[MERGE-GATES-PATHS][FAIL] expected path in both pull_request and push filters: $p (count=$count)" >&2
    exit 1
  fi
done

echo "[MERGE-GATES-PATHS][PASS] workflow trigger paths cover key merge-gate inputs in pull_request + push"
