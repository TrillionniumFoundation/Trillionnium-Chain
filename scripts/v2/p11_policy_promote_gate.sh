#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FROM=""
TO=""
DRY_RUN=0
APPROVED=0
POLICY_FILE="config/alert-policy/current.json"

usage() {
  cat <<'EOF'
Usage:
  scripts/v2/p11_policy_promote_gate.sh --from staging --to prod [--dry-run] [--approve] [--policy <path>]

Behavior:
  - Enforces explicit --from staging --to prod.
  - Non-dry-run requires --approve (manual gate).
  - Calls scripts/v2/p11_policy_promote.sh after checks.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from) FROM="${2:-}"; shift 2 ;;
    --to) TO="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --approve|--yes) APPROVED=1; shift ;;
    --policy) POLICY_FILE="${2:-}"; shift 2 ;;
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
  echo "[P11][BLOCKED] missing approval for non-dry-run. Re-run with --approve" >&2
  exit 3
fi

CMD=("$ROOT/scripts/v2/p11_policy_promote.sh" --from "$FROM" --to "$TO" --policy "$POLICY_FILE")
if [[ "$DRY_RUN" -eq 1 ]]; then
  CMD+=(--dry-run)
fi

echo "[P11][gate] running: ${CMD[*]}"
"${CMD[@]}"
