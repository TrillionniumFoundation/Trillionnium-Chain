#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNBOOK="$ROOT/docs/runbooks/enterprise_onboarding_runbook_v1.md"

if [[ ! -f "$RUNBOOK" ]]; then
  echo "[FAIL] missing runbook: $RUNBOOK" >&2
  exit 1
fi

if grep -Eiq -- 'trnm-onboard rollback .*--(force|yes)\b' "$RUNBOOK"; then
  echo "[FAIL] rollback command examples must be fail-closed and must not include --force/--yes" >&2
  exit 1
fi

if ! grep -Fq -- '--dry-run' "$RUNBOOK"; then
  echo "[FAIL] rollback section must include --dry-run preflight example" >&2
  exit 1
fi

echo "[PASS] E3 rollback command examples stay fail-closed (no --force/--yes) and include --dry-run"
