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

anchor_phrase='单事件回滚建议追加 `--request-id <request_id>` 形成审计锚点（与 root_cause_tag 一起固化）。'
if ! grep -Fq -- "$anchor_phrase" "$RUNBOOK"; then
  echo "[FAIL] missing rollback request_id anchor guidance" >&2
  exit 1
fi

request_cmd='trnm-onboard rollback --org-id <org_id> --env <env> --change-ticket-id <change_ticket_id> --root-cause-tag <root_cause_tag> --request-id <request_id>'
request_dry_run_cmd="$request_cmd --dry-run"

if ! grep -Fq -- "$request_cmd" "$RUNBOOK"; then
  echo "[FAIL] missing rollback request_id anchor command template" >&2
  exit 1
fi

if ! grep -Fq -- "$request_dry_run_cmd" "$RUNBOOK"; then
  echo "[FAIL] missing rollback request_id anchor dry-run command template" >&2
  exit 1
fi

echo "[PASS] E3 runbook includes request_id-anchored rollback templates"
