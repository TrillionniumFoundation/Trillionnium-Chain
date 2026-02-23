#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${1:-$ROOT/run/pr9/alert-thresholds.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[ERR] env file not found: $ENV_FILE" >&2
  echo "Hint: run scripts/v2/pr9_generate_alert_thresholds_env.py first" >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a
source "$ENV_FILE"
set +a

cat <<EOF
[DRY-RUN] Would inject the following env vars (no online changes):
  WARN_UNRESOLVED_CHALLENGES=${WARN_UNRESOLVED_CHALLENGES:-}
  FAIL_UNRESOLVED_CHALLENGES=${FAIL_UNRESOLVED_CHALLENGES:-}
  WARN_FORFEITS_DAILY_INCREASE=${WARN_FORFEITS_DAILY_INCREASE:-}
  FAIL_FORFEITS_DAILY_INCREASE=${FAIL_FORFEITS_DAILY_INCREASE:-}
  WARN_ESCROW_NONZERO_HOURS=${WARN_ESCROW_NONZERO_HOURS:-}
  FAIL_ESCROW_NONZERO_HOURS=${FAIL_ESCROW_NONZERO_HOURS:-}

[DRY-RUN] Command preview:
  WARN_UNRESOLVED_CHALLENGES=${WARN_UNRESOLVED_CHALLENGES:-} \\
  FAIL_UNRESOLVED_CHALLENGES=${FAIL_UNRESOLVED_CHALLENGES:-} \\
  WARN_FORFEITS_DAILY_INCREASE=${WARN_FORFEITS_DAILY_INCREASE:-} \\
  FAIL_FORFEITS_DAILY_INCREASE=${FAIL_FORFEITS_DAILY_INCREASE:-} \\
  WARN_ESCROW_NONZERO_HOURS=${WARN_ESCROW_NONZERO_HOURS:-} \\
  FAIL_ESCROW_NONZERO_HOURS=${FAIL_ESCROW_NONZERO_HOURS:-} \\
  $ROOT/scripts/v2/pr6_alert_rules_gate.sh

[DRY-RUN] Rollback plan:
  1) Keep previous env snapshot as run/pr9/alert-thresholds.previous.env.
  2) To rollback, swap file back and rerun gate with previous env.
  3) Or run scripts/v2/pr9_rollback_thresholds.sh.
EOF
