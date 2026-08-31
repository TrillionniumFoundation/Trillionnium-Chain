#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/trnm-gate-quick-check.yml"

required_paths=(
  "config/alert-policy/**"
  "docs/runbooks/enterprise_onboarding_runbook_v1.md"
)

for path in "${required_paths[@]}"; do
  count="$(grep -Fc -- "- '$path'" "$WF" || true)"
  if [[ "$count" -lt 2 ]]; then
    echo "[FAIL] expected quick-check path in pull_request and push filters: $path (count=$count)" >&2
    exit 1
  fi
done

echo "[PASS] quick-check paths cover alert policy and the runbook-backed E3 regressions"
