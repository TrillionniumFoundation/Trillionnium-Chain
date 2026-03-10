#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNBOOK="$ROOT/docs/runbooks/enterprise_onboarding_runbook_v1.md"

if [[ ! -f "$RUNBOOK" ]]; then
  echo "[FAIL] missing runbook: $RUNBOOK" >&2
  exit 1
fi

if ! grep -Fq -- 'env TZ=UTC LC_ALL=C LANG=C trnm-onboard rollback --org-id <org_id> --env <env> --change-ticket-id <change_ticket_id> --root-cause-tag <root_cause_tag> --dry-run' "$RUNBOOK"; then
  echo "[FAIL] missing deterministic rollback --dry-run template with canonical env prefix" >&2
  exit 1
fi

if ! grep -Fq -- 'env TZ=UTC LC_ALL=C LANG=C trnm-onboard replay --request-id <request_id> --expect-status reverted --expect-idempotent --dry-run' "$RUNBOOK"; then
  echo "[FAIL] missing deterministic replay --dry-run template with canonical env prefix" >&2
  exit 1
fi

echo "[PASS] E3 runbook includes deterministic env prefix for rollback/replay dry-run commands"
