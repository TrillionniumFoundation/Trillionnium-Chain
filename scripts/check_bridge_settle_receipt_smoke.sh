#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

mkdir -p "$ROOT/run/health"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$ROOT/run/health/bridge-settle-receipt-smoke-${TS}.log"
BRIDGE_RELAY_MANIFEST="$ROOT/contracts/bridge-relay/Cargo.toml"
TRNM_TYPES_MANIFEST="$ROOT/trillionnium/Cargo.toml"

preflight_check() {
  local path="$1"
  local hint="$2"
  if [[ ! -f "$path" ]]; then
    echo "[FAIL] missing required manifest: $path" | tee -a "$OUT"
    echo "[HINT] $hint" | tee -a "$OUT"
    exit 1
  fi
}

preflight_check "$BRIDGE_RELAY_MANIFEST" "Expected current repo layout contracts/bridge-relay; treat legacy contracts-rust/bridge-relay references as stale."
preflight_check "$TRNM_TYPES_MANIFEST" "Expected trillionnium/Cargo.toml for trnm-types smoke coverage."

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
  cargo test --manifest-path "$BRIDGE_RELAY_MANIFEST" --lib --tests submit_proof_rejects_non_success_tx_receipt -- --nocapture

run_step "bridge-relay: keep proof replay bound after finalize terminal state" \
  cargo test --manifest-path "$BRIDGE_RELAY_MANIFEST" --lib --tests submit_proof_replay_after_finalize_stays_proof_replay_bound -- --nocapture

run_step "bridge-relay: keep proof replay rejection side-effect free" \
  cargo test --manifest-path "$BRIDGE_RELAY_MANIFEST" --lib --tests proof_replay_rejection_is_side_effect_free -- --nocapture

run_step "bridge-relay: reject finalize when receipt status is non-success" \
  cargo test --manifest-path "$BRIDGE_RELAY_MANIFEST" --lib --tests finalize_settlement_rejects_non_success_tx_receipt -- --nocapture

run_step "bridge-relay: reject stale-config finalize after governance change" \
  cargo test --manifest-path "$BRIDGE_RELAY_MANIFEST" --lib --tests finalize_settlement_rejects_stale_config_version_after_governance_change -- --nocapture

run_step "bridge-relay: reject target-bridge mismatch without audit side effects" \
  cargo test --manifest-path "$BRIDGE_RELAY_MANIFEST" --lib --tests finalize_settlement_rejects_target_bridge_mismatch_without_audit_side_effects -- --nocapture

run_step "bridge-relay: keep finalize terminal by settlement id even with fresh nonce" \
  cargo test --manifest-path "$BRIDGE_RELAY_MANIFEST" --lib --tests finalize_settlement_is_idempotent_by_settlement_id_even_with_new_nonce -- --nocapture

run_step "bridge-relay: duplicate finalize stays side-effect free" \
  cargo test --manifest-path "$BRIDGE_RELAY_MANIFEST" --lib --tests duplicate_finalize_is_side_effect_free -- --nocapture

run_step "bridge-relay: rollback proof side effects when finalize hits nonce collision" \
  cargo test --manifest-path "$BRIDGE_RELAY_MANIFEST" --lib --tests finalize_settlement_nonce_collision_rolls_back_proof_side_effects -- --nocapture

run_step "bridge-relay: keep finalized settlement terminal even with fresh nonce + bad receipt" \
  cargo test --manifest-path "$BRIDGE_RELAY_MANIFEST" --lib --tests duplicate_finalize_with_fresh_nonce_and_bad_receipt_still_stops_at_terminal_state -- --nocapture

run_step "bridge-relay: keep finalized settlement terminal even after governance config drift" \
  cargo test --manifest-path "$BRIDGE_RELAY_MANIFEST" --lib --tests duplicate_finalize_with_stale_config_version_after_governance_change_still_stops_at_terminal_state -- --nocapture

run_step "bridge-relay: keep finalized settlement terminal even with fresh config after governance drift" \
  cargo test --manifest-path "$BRIDGE_RELAY_MANIFEST" --lib --tests duplicate_finalize_with_fresh_config_version_after_governance_change_still_stops_at_terminal_state -- --nocapture

run_step "bridge-relay: reject stale governance write with stale config version" \
  cargo test --manifest-path "$BRIDGE_RELAY_MANIFEST" --lib --tests governance_write_with_stale_config_version_is_fail_closed_and_side_effect_free -- --nocapture

run_step "bridge-relay: reject stale validator rotation with stale config version" \
  cargo test --manifest-path "$BRIDGE_RELAY_MANIFEST" --lib --tests stale_validator_rotation_is_fail_closed_and_side_effect_free -- --nocapture

run_step "trnm-types: enforce receipt success for finalize helper" \
  cargo test --manifest-path "$TRNM_TYPES_MANIFEST" -p trnm-types --lib settlement_state_machine_enforces_receipt_success_for_finalization -- --nocapture

run_step "trnm-types: reject settlement finalization with failed tx receipt" \
  cargo test --manifest-path "$TRNM_TYPES_MANIFEST" -p trnm-types --test x3_settlement_stale_pending_replay settlement_finalization_rejects_failed_tx_receipt -- --nocapture

echo "\n[OK] bridge settle receipt smoke passed: $OUT" | tee -a "$OUT"
