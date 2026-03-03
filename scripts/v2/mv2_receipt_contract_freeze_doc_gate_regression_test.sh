#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SNAPSHOT_SPEC="$ROOT/docs/development/WEB4_PHASE_B_MILESTONE_SNAPSHOT_2026-02-28.md"
MASTER_SPEC="$ROOT/docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md"
GATE="$ROOT/scripts/v2/mv2_receipt_contract_freeze_doc_gate.sh"

if [[ ! -f "$SNAPSHOT_SPEC" ]]; then
  echo "[FAIL] missing snapshot spec: $SNAPSHOT_SPEC" >&2
  exit 1
fi

if [[ ! -f "$MASTER_SPEC" ]]; then
  echo "[FAIL] missing master spec: $MASTER_SPEC" >&2
  exit 1
fi

if [[ ! -x "$GATE" ]]; then
  echo "[FAIL] gate script is missing or not executable: $GATE" >&2
  exit 1
fi

tmp_snapshot="$(mktemp)"
tmp_master="$(mktemp)"
cp "$SNAPSHOT_SPEC" "$tmp_snapshot"
cp "$MASTER_SPEC" "$tmp_master"
cleanup() {
  cp "$tmp_snapshot" "$SNAPSHOT_SPEC"
  cp "$tmp_master" "$MASTER_SPEC"
  rm -f "$tmp_snapshot" "$tmp_master"
}
trap cleanup EXIT

# Baseline: current specs should satisfy the gate.
"$GATE"

# Regression 1: remove canonical field contract phrase from snapshot; gate must fail-closed.
python3 - <<'PY' "$SNAPSHOT_SPEC"
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
  echo "[FAIL] MV2 gate should fail when snapshot unified field contract phrase is removed" >&2
  exit 1
fi

# Restore snapshot and validate baseline again before next mutation.
cp "$tmp_snapshot" "$SNAPSHOT_SPEC"
"$GATE"

# Regression 2: remove canonical fail-closed phrase from master; gate must fail-closed.
python3 - <<'PY' "$MASTER_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "不允许静默成功"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, "允许成功", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when master fail-closed phrase is removed" >&2
  exit 1
fi

echo "[PASS] MV2 receipt contract freeze doc gate fails-closed on snapshot + master phrase drift"
