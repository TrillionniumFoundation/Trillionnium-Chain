#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

mkdir -p "$ROOT/run/health"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$ROOT/run/health/bridge-settle-receipt-smoke-${TS}.log"

run_step() {
  local description="$1"
  shift
  echo "\n[STEP] $description" | tee -a "$OUT"
  if "$@" | tee -a "$OUT"; then
    echo "[OK] $description" | tee -a "$OUT"
  else
    status=$?
    echo "[FAIL] $description (exit=$status)" | tee -a "$OUT"
    return $status
  fi
}

run_step "bridge-relay: reject proof when receipt status is non-success" \
  bash -c 'cargo test --manifest-path contracts-rust/bridge-relay/Cargo.toml --lib --tests submit_proof_rejects_non_success_tx_receipt -- --nocapture'

run_step "bridge-relay: reject finalize when receipt status is non-success" \
  bash -c 'cargo test --manifest-path contracts-rust/bridge-relay/Cargo.toml --lib --tests finalize_settlement_rejects_non_success_tx_receipt -- --nocapture'

run_step "bridge-relay: reject stale-config finalize after governance change" \
  bash -c 'cargo test --manifest-path contracts-rust/bridge-relay/Cargo.toml --lib --tests finalize_settlement_rejects_stale_config_version_after_governance_change -- --nocapture'

run_step "trnm-types: enforce receipt success for finalize helper" \
  bash -c 'cargo test --manifest-path trillionnium-rust/Cargo.toml -p trnm-types --lib settlement_state_machine_enforces_receipt_success_for_finalization -- --nocapture'

run_step "trnm-types: reject settlement finalization with failed tx receipt" \
  bash -c 'cargo test --manifest-path trillionnium-rust/Cargo.toml -p trnm-types --test x3_settlement_stale_pending_replay settlement_finalization_rejects_failed_tx_receipt -- --nocapture'

echo "\n[OK] bridge settle receipt smoke passed: $OUT" | tee -a "$OUT"
