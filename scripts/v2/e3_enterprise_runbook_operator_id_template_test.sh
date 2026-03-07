#!/usr/bin/env bash
set -euo pipefail

# Pin UTF-8 locale so Chinese runbook assertions are deterministic across shells.
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNBOOK="$ROOT/docs/runbooks/enterprise_onboarding_runbook_v1.md"

if [[ ! -f "$RUNBOOK" ]]; then
  echo "[FAIL] missing runbook: $RUNBOOK" >&2
  exit 1
fi

base_cmd='trnm-onboard rollback --org-id <org_id> --env <env> --change-ticket-id <change_ticket_id> --operator-id <operator_id> --root-cause-tag <root_cause_tag>'
request_cmd="$base_cmd --request-id <request_id>"
dry_run_cmd="$base_cmd --dry-run"

if ! grep -Fq -- "--operator-id <operator_id>" "$RUNBOOK"; then
  echo "[FAIL] rollback template must pin --operator-id <operator_id>" >&2
  exit 1
fi

for cmd in "$base_cmd" "$dry_run_cmd" "$request_cmd"; do
  if ! grep -Fq -- "$cmd" "$RUNBOOK"; then
    echo "[FAIL] missing rollback command variant: $cmd" >&2
    exit 1
  fi
done

if ! grep -Fq -- "回滚执行人标识（operator_id）与变更单绑定记录" "$RUNBOOK"; then
  echo "[FAIL] evidence checklist missing operator_id binding record" >&2
  exit 1
fi

echo "[PASS] E3 runbook pins operator-id in rollback templates and evidence checklist"
