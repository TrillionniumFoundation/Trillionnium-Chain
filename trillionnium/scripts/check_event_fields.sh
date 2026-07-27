#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

mkdir -p run
OUT="run/event-field-check.log"
WAL_DIR="run/event-field-check-wal"
rm -rf "$WAL_DIR"

cargo run -q -p trnm-node --bin trnm-sim -- \
  --config configs/node1.toml \
  --block-ms 1 \
  --max-blocks 8 \
  --txs-per-block 1 \
  --demo-tasks 1 \
  --demo-keys 1 \
  --parallel-workers 2 \
  --bft-wal-dir "$WAL_DIR" > "$OUT"

required_common=(
  "event_schema=v1"
  "event_type="
  "task_id="
  "from_status="
  "to_status="
  "actor="
  "signer="
  "challenger="
  "tx_hash="
  "tx_id="
  "block_height="
  "state_root="
  "ts_unix_ms="
)

common_line=$(grep '^\[event\] ' "$OUT" | head -n 1 || true)
if [[ -z "$common_line" ]]; then
  echo "no [event] line found in $OUT" >&2
  exit 2
fi

for token in "${required_common[@]}"; do
  if [[ "$common_line" != *"$token"* ]]; then
    echo "missing common field '$token' in event line: $common_line" >&2
    exit 3
  fi
done

resolve_line=$(grep '^\[event\] .*event_type=resolve ' "$OUT" | head -n 1 || true)
if [[ -z "$resolve_line" ]]; then
  if [[ "${ALLOW_MISSING_RESOLVE_EVENT:-0}" == "1" ]]; then
    echo "[WARN] no resolve event line found in $OUT (ALLOW_MISSING_RESOLVE_EVENT=1)"
    echo "[OK] event common field check passed (resolve skipped): $OUT"
    exit 0
  fi
  echo "no resolve event line found in $OUT" >&2
  exit 4
fi

for token in "slash_worker=" "resolution_code="; do
  if [[ "$resolve_line" != *"$token"* ]]; then
    echo "missing resolve field '$token' in line: $resolve_line" >&2
    exit 5
  fi
done

echo "[OK] event field check passed: $OUT"
