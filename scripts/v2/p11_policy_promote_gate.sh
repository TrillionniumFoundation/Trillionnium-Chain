#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FROM=""
TO=""
DRY_RUN=0
APPROVED=0
APPROVAL_CODE=""
APPROVED_BY=""
REVIEWED_BY=""
POLICY_FILE="config/alert-policy/current.json"

usage() {
  cat <<'EOF'
Usage:
  scripts/v2/p11_policy_promote_gate.sh --from staging --to prod [--dry-run] [--approve --approval-code <code> --approved-by <id> --reviewed-by <id>] [--policy <path>]

Behavior:
  - Enforces explicit --from staging --to prod.
  - Non-dry-run requires --approve + --approval-code + --approved-by + --reviewed-by.
  - approved-by/reviewed-by must be two distinct identities.
  - Calls scripts/v2/p11_policy_promote.sh after checks.
EOF
}

require_arg_value() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == --* ]]; then
    echo "[P11][FAIL] missing value for $flag" >&2
    usage
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from)
      require_arg_value "$1" "${2:-}"
      FROM="$2"
      shift 2 ;;
    --to)
      require_arg_value "$1" "${2:-}"
      TO="$2"
      shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --approve|--yes) APPROVED=1; shift ;;
    --policy)
      require_arg_value "$1" "${2:-}"
      POLICY_FILE="$2"
      shift 2 ;;
    --approval-code)
      require_arg_value "$1" "${2:-}"
      APPROVAL_CODE="$2"
      shift 2 ;;
    --approved-by)
      require_arg_value "$1" "${2:-}"
      APPROVED_BY="$2"
      shift 2 ;;
    --reviewed-by)
      require_arg_value "$1" "${2:-}"
      REVIEWED_BY="$2"
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "[P11][FAIL] unknown arg: $1" >&2
      usage
      exit 2 ;;
  esac
done

if [[ "$FROM" != "staging" || "$TO" != "prod" ]]; then
  echo "[P11][FAIL] gate requires explicit --from staging --to prod" >&2
  exit 2
fi

if [[ "$DRY_RUN" -eq 0 && "$APPROVED" -ne 1 ]]; then
  echo "[P11][BLOCKED] missing approval for non-dry-run. Re-run with --approve --approval-code <code>" >&2
  exit 3
fi
if [[ "$DRY_RUN" -eq 0 && -z "$APPROVAL_CODE" ]]; then
  echo "[P11][BLOCKED] missing --approval-code for non-dry-run" >&2
  exit 3
fi
if [[ "$DRY_RUN" -eq 0 && -z "$APPROVED_BY" ]]; then
  echo "[P11][BLOCKED] missing --approved-by for non-dry-run" >&2
  exit 3
fi
if [[ "$DRY_RUN" -eq 0 && -z "$REVIEWED_BY" ]]; then
  echo "[P11][BLOCKED] missing --reviewed-by for non-dry-run" >&2
  exit 3
fi
if [[ "$DRY_RUN" -eq 0 && "$APPROVED_BY" == "$REVIEWED_BY" ]]; then
  echo "[P11][BLOCKED] approver identities must be distinct (--approved-by != --reviewed-by)" >&2
  exit 3
fi

CMD=("$ROOT/scripts/v2/p11_policy_promote.sh" --from "$FROM" --to "$TO" --policy "$POLICY_FILE")
if [[ "$DRY_RUN" -eq 1 ]]; then
  CMD+=(--dry-run)
else
  CMD+=(--approve --approval-code "$APPROVAL_CODE" --approved-by "$APPROVED_BY" --reviewed-by "$REVIEWED_BY")
fi

echo "[P11][gate] running: scripts/v2/p11_policy_promote.sh --from $FROM --to $TO --policy $POLICY_FILE"
"${CMD[@]}"
