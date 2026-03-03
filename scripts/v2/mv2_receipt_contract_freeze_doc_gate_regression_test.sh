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

# Restore master and validate baseline before next mutation.
cp "$tmp_master" "$MASTER_SPEC"
"$GATE"

# Regression 3: remove canonical frozen error-code token from master; gate must fail-closed.
python3 - <<'PY' "$MASTER_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "ERR_M2V2_PROOF_MISSING"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, "ERR_M2V2_PROOF", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when master frozen error-code token is removed" >&2
  exit 1
fi

# Restore master and validate baseline before next mutation.
cp "$tmp_master" "$MASTER_SPEC"
"$GATE"

# Regression 4: remove canonical frozen error-code token from snapshot; gate must fail-closed.
python3 - <<'PY' "$SNAPSHOT_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "ERR_M2V2_PROOF_LATE"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, "ERR_M2V2_PROOF", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when snapshot frozen error-code token is removed" >&2
  exit 1
fi

# Restore snapshot and validate baseline before next mutation.
cp "$tmp_snapshot" "$SNAPSHOT_SPEC"
"$GATE"

# Regression 5: remove canonical state transition mapping from master; gate must fail-closed.
python3 - <<'PY' "$MASTER_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "pending_proof -> disputed(proof_missing|proof_late|proof_invalid) -> downgraded(settlement_degraded)"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, "pending_proof -> disputed -> downgraded", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when master state transition mapping phrase is removed" >&2
  exit 1
fi

# Restore master and validate baseline before next mutation.
cp "$tmp_master" "$MASTER_SPEC"
"$GATE"

# Regression 6: remove canonical state transition mapping from snapshot; gate must fail-closed.
python3 - <<'PY' "$SNAPSHOT_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "pending_proof -> disputed(proof_missing|proof_late|proof_invalid) -> downgraded(settlement_degraded)"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, "pending_proof -> disputed -> downgraded", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when snapshot state transition mapping phrase is removed" >&2
  exit 1
fi

# Restore snapshot and validate baseline before next mutation.
cp "$tmp_snapshot" "$SNAPSHOT_SPEC"
"$GATE"

# Regression 7: keep all frozen tokens but reorder snapshot error mapping; gate must fail on snapshot/master parity drift.
python3 - <<'PY' "$SNAPSHOT_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "- 最小错误码映射（冻结）：`proof_missing -> ERR_M2V2_PROOF_MISSING`、`proof_late -> ERR_M2V2_PROOF_LATE`、`proof_invalid -> ERR_M2V2_PROOF_INVALID`、`settlement_degraded -> ERR_M2V2_SETTLEMENT_DEGRADED`。"
replacement = "- 最小错误码映射（冻结）：`proof_late -> ERR_M2V2_PROOF_LATE`、`proof_missing -> ERR_M2V2_PROOF_MISSING`、`proof_invalid -> ERR_M2V2_PROOF_INVALID`、`settlement_degraded -> ERR_M2V2_SETTLEMENT_DEGRADED`。"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, replacement, 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when snapshot/master frozen error mapping lines drift despite token presence" >&2
  exit 1
fi

# Restore snapshot and validate baseline before next mutation.
cp "$tmp_snapshot" "$SNAPSHOT_SPEC"
"$GATE"

# Regression 8: duplicate frozen error mapping line in snapshot; gate must fail on non-unique canonical contract line.
python3 - <<'PY' "$SNAPSHOT_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "- 最小错误码映射（冻结）：`proof_missing -> ERR_M2V2_PROOF_MISSING`、`proof_late -> ERR_M2V2_PROOF_LATE`、`proof_invalid -> ERR_M2V2_PROOF_INVALID`、`settlement_degraded -> ERR_M2V2_SETTLEMENT_DEGRADED`。"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, f"{needle}\n{needle}", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when snapshot has duplicated frozen error mapping line" >&2
  exit 1
fi

# Restore snapshot and validate baseline before next mutation.
cp "$tmp_snapshot" "$SNAPSHOT_SPEC"
"$GATE"

# Regression 9: duplicate frozen state transition mapping line in master; gate must fail on non-unique canonical state mapping line.
python3 - <<'PY' "$MASTER_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "- 最小状态迁移映射（冻结）：`pending_proof -> disputed(proof_missing|proof_late|proof_invalid) -> downgraded(settlement_degraded)`。"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, f"{needle}\n{needle}", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when master has duplicated frozen state transition mapping line" >&2
  exit 1
fi

echo "[PASS] MV2 receipt contract freeze doc gate fails-closed on snapshot + master phrase/parity drift"
