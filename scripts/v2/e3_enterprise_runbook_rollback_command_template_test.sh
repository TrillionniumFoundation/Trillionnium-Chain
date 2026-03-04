#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNBOOK="$ROOT/docs/runbooks/enterprise_onboarding_runbook_v1.md"

if [[ ! -f "$RUNBOOK" ]]; then
  echo "[FAIL] missing runbook: $RUNBOOK" >&2
  exit 1
fi

base_cmd='trnm-onboard rollback --org-id <org_id> --env <env> --change-ticket-id <change_ticket_id> --root-cause-tag <tag>'
dry_run_cmd="$base_cmd --dry-run"

if ! grep -Fq -- "$base_cmd" "$RUNBOOK"; then
  echo "[FAIL] missing canonical rollback command template" >&2
  exit 1
fi

if ! grep -Fq -- "$dry_run_cmd" "$RUNBOOK"; then
  echo "[FAIL] missing canonical rollback --dry-run template" >&2
  exit 1
fi

base_count="$(grep -F -- "$base_cmd" "$RUNBOOK" | wc -l | tr -d ' ')"
dry_run_count="$(grep -F -- "$dry_run_cmd" "$RUNBOOK" | wc -l | tr -d ' ')"

if [[ "$base_count" -ne 2 ]]; then
  echo "[FAIL] expected rollback command template to appear twice (normal + dry-run prefix), got $base_count" >&2
  exit 1
fi

if [[ "$dry_run_count" -ne 1 ]]; then
  echo "[FAIL] expected rollback --dry-run template to appear exactly once, got $dry_run_count" >&2
  exit 1
fi

echo "[PASS] E3 runbook pins canonical rollback command template and dry-run variant"
