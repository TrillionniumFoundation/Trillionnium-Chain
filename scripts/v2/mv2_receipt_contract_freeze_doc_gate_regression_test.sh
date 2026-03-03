#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/development/WEB4_PHASE_B_MILESTONE_SNAPSHOT_2026-02-28.md"
GATE="$ROOT/scripts/v2/mv2_receipt_contract_freeze_doc_gate.sh"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing snapshot spec: $SPEC" >&2
  exit 1
fi

if [[ ! -x "$GATE" ]]; then
  echo "[FAIL] gate script is missing or not executable: $GATE" >&2
  exit 1
fi

tmp="$(mktemp)"
cp "$SPEC" "$tmp"
cleanup() {
  cp "$tmp" "$SPEC"
  rm -f "$tmp"
}
trap cleanup EXIT

# Baseline: current spec should satisfy the gate.
"$GATE"

# Regression: remove a canonical contract phrase; gate must fail-closed.
python3 - <<'PY' "$SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "task_id/proof_type/verdict/verified_at/cost_hint"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, "task_id/proof_type/verdict/verified_at", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when unified field contract phrase is removed" >&2
  exit 1
fi

echo "[PASS] MV2 receipt contract freeze doc gate fails-closed on contract phrase drift"