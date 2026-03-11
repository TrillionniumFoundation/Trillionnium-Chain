#!/usr/bin/env bash
set -euo pipefail

# Pin UTF-8 locale categories so Chinese runbook assertions are deterministic across shells.
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export LC_CTYPE=C.UTF-8

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNBOOK="$ROOT/docs/runbooks/enterprise_onboarding_runbook_v1.md"

if [[ ! -f "$RUNBOOK" ]]; then
  echo "[FAIL] missing runbook: $RUNBOOK" >&2
  exit 1
fi

required_cmd='env TZ=UTC LC_ALL=C LANG=C trnm-onboard replay --request-id <request_id> --expect-status reverted --expect-idempotent --dry-run'
if ! grep -Fq -- "$required_cmd" "$RUNBOOK"; then
  echo "[FAIL] missing deterministic replay dry-run command template" >&2
  exit 1
fi

echo "[PASS] E3 runbook pins deterministic replay dry-run command template"
