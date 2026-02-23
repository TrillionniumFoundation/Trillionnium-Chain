#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CUR="${1:-$ROOT/run/pr9/alert-thresholds.env}"
PREV="${2:-$ROOT/run/pr9/alert-thresholds.previous.env}"

if [[ ! -f "$PREV" ]]; then
  echo "[ERR] rollback source not found: $PREV" >&2
  exit 1
fi

mkdir -p "$(dirname "$CUR")"
cp "$PREV" "$CUR"

echo "[OK] Restored $CUR from $PREV"
echo "[NEXT] You can re-run with previous thresholds:"
echo "       scripts/v2/pr9_apply_thresholds_dry_run.sh $CUR"
