#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SNAPSHOT_SPEC="$ROOT/docs/archive/web4-history/WEB4_PHASE_B_MILESTONE_SNAPSHOT_2026-02-28.md"
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
"$GATE" >/dev/null

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
"$GATE" >/dev/null

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
"$GATE" >/dev/null

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
"$GATE" >/dev/null

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
"$GATE" >/dev/null

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
"$GATE" >/dev/null

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
"$GATE" >/dev/null

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
"$GATE" >/dev/null

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
"$GATE" >/dev/null

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

# Restore master and validate baseline before next mutation.
cp "$tmp_master" "$MASTER_SPEC"
"$GATE" >/dev/null

# Regression 10: keep all frozen state tokens but reorder master mapping; gate must fail on snapshot/master state mapping parity drift.
python3 - <<'PY' "$MASTER_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "- 最小状态迁移映射（冻结）：`pending_proof -> disputed(proof_missing|proof_late|proof_invalid) -> downgraded(settlement_degraded)`。"
replacement = "- 最小状态迁移映射（冻结）：`pending_proof -> disputed(proof_invalid|proof_missing|proof_late) -> downgraded(settlement_degraded)`。"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, replacement, 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when snapshot/master frozen state mapping lines drift despite token presence" >&2
  exit 1
fi

# Restore master and validate baseline before next mutation.
cp "$tmp_master" "$MASTER_SPEC"
"$GATE" >/dev/null

# Regression 11: duplicate MV2 master anchor heading; gate must fail on non-unique anchor.
python3 - <<'PY' "$MASTER_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "### 10.3 Lane MV（2026-03-03）V2 回执契约冻结主文档锚点"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, f"{needle}\n{needle}", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when master MV2 anchor heading is duplicated" >&2
  exit 1
fi

# Restore master and validate baseline before next mutation.
cp "$tmp_master" "$MASTER_SPEC"
"$GATE" >/dev/null

# Regression 12: duplicate MV2 snapshot anchor heading; gate must fail on non-unique anchor.
python3 - <<'PY' "$SNAPSHOT_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "### MV-2：V2 回执接入前的契约冻结（Receipt Contract Freeze）"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, f"{needle}\n{needle}", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when snapshot MV2 anchor heading is duplicated" >&2
  exit 1
fi

# Restore snapshot and validate baseline before next mutation.
cp "$tmp_snapshot" "$SNAPSHOT_SPEC"
"$GATE" >/dev/null

# Regression 13: duplicate canonical unified field-contract phrase in master; gate must fail on non-unique contract line.
python3 - <<'PY' "$MASTER_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "task_id/proof_type/verdict/verified_at/cost_hint"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, f"{needle}\n{needle}", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when master has duplicated unified field-contract phrase" >&2
  exit 1
fi

# Restore master and validate baseline before next mutation.
cp "$tmp_master" "$MASTER_SPEC"
"$GATE" >/dev/null

# Regression 13b: duplicate canonical unified field-contract phrase in snapshot; gate must fail on non-unique contract line.
python3 - <<'PY' "$SNAPSHOT_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "task_id/proof_type/verdict/verified_at/cost_hint"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, f"{needle}\n{needle}", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when snapshot has duplicated unified field-contract phrase" >&2
  exit 1
fi

# Restore snapshot and validate baseline before next mutation.
cp "$tmp_snapshot" "$SNAPSHOT_SPEC"
"$GATE" >/dev/null

# Regression 14: duplicate canonical fail-closed phrase in snapshot; gate must fail on non-unique fail-closed contract line.
python3 - <<'PY' "$SNAPSHOT_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "不允许静默成功"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, f"{needle}\n{needle}", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when snapshot has duplicated fail-closed phrase" >&2
  exit 1
fi

# Restore snapshot and validate baseline before next mutation.
cp "$tmp_snapshot" "$SNAPSHOT_SPEC"
"$GATE" >/dev/null

# Regression 15: alter master MV2 anchor heading metadata (date drift); gate must fail on missing canonical anchor.
python3 - <<'PY' "$MASTER_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "### 10.3 Lane MV（2026-03-03）V2 回执契约冻结主文档锚点"
replacement = "### 10.3 Lane MV（2026-03-04）V2 回执契约冻结主文档锚点"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, replacement, 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when master MV2 anchor heading drifts from canonical frozen value" >&2
  exit 1
fi

# Restore master and validate baseline before next mutation.
cp "$tmp_master" "$MASTER_SPEC"
"$GATE" >/dev/null

# Regression 16: duplicate frozen state transition mapping line in snapshot; gate must fail on non-unique canonical state mapping line.
python3 - <<'PY' "$SNAPSHOT_SPEC"
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
  echo "[FAIL] MV2 gate should fail when snapshot has duplicated frozen state transition mapping line" >&2
  exit 1
fi

# Restore snapshot and validate baseline before next mutation.
cp "$tmp_snapshot" "$SNAPSHOT_SPEC"
"$GATE" >/dev/null

# Regression 17: duplicate canonical fail-closed phrase in master; gate must fail on non-unique fail-closed contract line.
python3 - <<'PY' "$MASTER_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "不允许静默成功"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, f"{needle}\n{needle}", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when master has duplicated fail-closed phrase" >&2
  exit 1
fi

# Restore master and validate baseline before next mutation.
cp "$tmp_master" "$MASTER_SPEC"
"$GATE" >/dev/null

# Regression 18: duplicate frozen error mapping line in master; gate must fail on non-unique canonical error mapping line.
python3 - <<'PY' "$MASTER_SPEC"
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
  echo "[FAIL] MV2 gate should fail when master has duplicated frozen error mapping line" >&2
  exit 1
fi

# Restore master and validate baseline before next mutation.
cp "$tmp_master" "$MASTER_SPEC"
"$GATE" >/dev/null

# Regression 19: duplicate M2↔V2 boundary phrase in snapshot; gate must fail on ambiguous cross-track boundary anchor.
python3 - <<'PY' "$SNAPSHOT_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "M2↔V2"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, f"{needle}\n{needle}", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when snapshot duplicates M2↔V2 boundary phrase" >&2
  exit 1
fi

# Restore snapshot and validate baseline before next mutation.
cp "$tmp_snapshot" "$SNAPSHOT_SPEC"
"$GATE" >/dev/null

# Regression 20: duplicate M2↔V2 boundary phrase in master; gate must fail on ambiguous cross-track boundary anchor.
python3 - <<'PY' "$MASTER_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "M2↔V2"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, f"{needle}\n{needle}", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when master duplicates M2↔V2 boundary phrase" >&2
  exit 1
fi

# Restore master and validate baseline before next mutation.
cp "$tmp_master" "$MASTER_SPEC"
"$GATE" >/dev/null

# Regression 21: duplicate proof union phrase in snapshot; gate must fail on ambiguous proof adapter union anchor.
python3 - <<'PY' "$SNAPSHOT_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "fraud_proof | tee_receipt | zk_receipt"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, f"{needle}\n{needle}", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when snapshot duplicates proof union phrase" >&2
  exit 1
fi

# Restore snapshot and validate baseline before next mutation.
cp "$tmp_snapshot" "$SNAPSHOT_SPEC"
"$GATE" >/dev/null

# Regression 22: duplicate proof union anchor line in master; gate must fail on non-unique anchor line.
python3 - <<'PY' "$MASTER_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "- 锚点目标：把 `fraud_proof | tee_receipt | zk_receipt` 的统一回执字段固定到 Master，避免仅在专题文档生效。"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, f"{needle}\n{needle}", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when master duplicates proof union anchor line" >&2
  exit 1
fi

# Restore master and validate baseline before next mutation.
cp "$tmp_master" "$MASTER_SPEC"
"$GATE" >/dev/null

# Regression 23: duplicate proof union anchor line in snapshot; gate must fail on non-unique anchor line.
python3 - <<'PY' "$SNAPSHOT_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "- 明确 `fraud_proof | tee_receipt | zk_receipt` 在市场结算视角的最小统一字段（`task_id/proof_type/verdict/verified_at/cost_hint`）。"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, f"{needle}\n{needle}", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when snapshot duplicates proof union anchor line" >&2
  exit 1
fi

# Restore both specs and validate baseline before next mutation.
cp "$tmp_snapshot" "$SNAPSHOT_SPEC"
cp "$tmp_master" "$MASTER_SPEC"
"$GATE" >/dev/null

# Regression 24: reorder frozen error mapping identically in snapshot + master; gate must fail on canonical contract drift (not parity-only).
python3 - <<'PY' "$SNAPSHOT_SPEC" "$MASTER_SPEC"
from pathlib import Path
import sys

snapshot = Path(sys.argv[1])
master = Path(sys.argv[2])
needle = "- 最小错误码映射（冻结）：`proof_missing -> ERR_M2V2_PROOF_MISSING`、`proof_late -> ERR_M2V2_PROOF_LATE`、`proof_invalid -> ERR_M2V2_PROOF_INVALID`、`settlement_degraded -> ERR_M2V2_SETTLEMENT_DEGRADED`。"
replacement = "- 最小错误码映射（冻结）：`proof_late -> ERR_M2V2_PROOF_LATE`、`proof_missing -> ERR_M2V2_PROOF_MISSING`、`proof_invalid -> ERR_M2V2_PROOF_INVALID`、`settlement_degraded -> ERR_M2V2_SETTLEMENT_DEGRADED`。"
for spec in (snapshot, master):
    text = spec.read_text(encoding='utf-8')
    if needle not in text:
        raise SystemExit(f"missing expected baseline phrase in {spec}: {needle}")
    spec.write_text(text.replace(needle, replacement, 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when snapshot + master drift together from canonical frozen error mapping order" >&2
  exit 1
fi

# Restore specs and validate baseline before next mutation.
cp "$tmp_snapshot" "$SNAPSHOT_SPEC"
cp "$tmp_master" "$MASTER_SPEC"
"$GATE" >/dev/null

# Regression 25: duplicate "错误码与状态迁移表" phrase in master; gate must fail on ambiguous MV2 boundary clause.
python3 - <<'PY' "$MASTER_SPEC"
from pathlib import Path
import sys

spec = Path(sys.argv[1])
text = spec.read_text(encoding='utf-8')
needle = "错误码与状态迁移表"
if needle not in text:
    raise SystemExit(f"missing expected baseline phrase: {needle}")
spec.write_text(text.replace(needle, f"{needle}\n{needle}", 1), encoding='utf-8')
PY

if "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] MV2 gate should fail when master duplicates error/state-table boundary phrase" >&2
  exit 1
fi

echo "[PASS] MV2 receipt contract freeze doc gate fails-closed on snapshot + master phrase/parity drift"
