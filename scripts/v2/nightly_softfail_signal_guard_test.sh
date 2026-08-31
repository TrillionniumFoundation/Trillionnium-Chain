#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/rust-l1-nightly-health.yml"

[[ -f "$WF" ]] || { echo "[FAIL] missing workflow: $WF" >&2; exit 1; }

required_lines=(
  'id: pr5_reconcile_report'
  'id: pr6_daily_security_summary'
  'id: pr9_weekly_alert_governance'
  'id: p11_policy_rollback_guard'
  'id: pr7_alert_delivery_gate'
  'name: Aggregate nightly critical soft-fail signals'
  'steps.pr6_daily_security_summary.outcome'
  'steps.p11_policy_rollback_guard.outcome'
  'steps.pr7_alert_delivery_gate.outcome'
  'P11_ROLLBACK_GUARD_JSON_OUT="$p11_json"'
  'payload.get("would_rollback") is True'
  'nightly_critical_soft_fail'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$WF"; then
    echo "[FAIL] missing nightly soft-fail signal guard line: $line" >&2
    exit 1
  fi
done

python3 - <<'PY' "$WF"
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
pr7_pos = text.index('name: PR-7 alert delivery gate (non-gate, observable)')
p11_pos = text.index('name: Build P11 policy rollback guard (dry-run, observable)')
if pr7_pos >= p11_pos:
    raise SystemExit('[FAIL] P11 rollback guard must evaluate the current PR7 delivery state')
p11_block = text[p11_pos:text.index('name: PR-7 delivery end-to-end replay gate (hard)', p11_pos)]
if 'raise SystemExit("P11 dry-run detected a rollback condition")' not in p11_block:
    raise SystemExit('[FAIL] P11 step must convert would_rollback/status=FAIL into a failed outcome')
critical_tokens = [
    '| security | pr6_daily_security_summary | critical | ${pr6_outcome} |',
    '| delivery_guard | p11_policy_rollback_guard | critical | ${p11_outcome} |',
    '| delivery | pr7_alert_delivery_gate | critical | ${pr7_outcome} |',
]
for token in critical_tokens:
    if token not in text:
        raise SystemExit(f"[FAIL] missing critical soft-fail aggregation token: {token}")
if 'exit 1' not in text.split('name: Aggregate nightly critical soft-fail signals', 1)[1]:
    raise SystemExit('[FAIL] aggregate nightly soft-fail step must fail when critical signals are present')
print('[PASS] nightly soft-fail signals are aggregated and critical paths are no longer silently green')
PY
