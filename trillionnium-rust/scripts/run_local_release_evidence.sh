#!/usr/bin/env bash
set -u -o pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

REPO_ROOT="$(cd "$ROOT/.." && pwd)"

TS="$(date -u +%Y%m%d-%H%M%S)"
BASE_OUT="${OUT_DIR:-$ROOT/run/health}"
EVIDENCE_DIR="$BASE_OUT/evidence-$TS"
SUMMARY="$EVIDENCE_DIR/summary.txt"
mkdir -p "$EVIDENCE_DIR"

PASS_COUNT=0
FAIL_COUNT=0

log() {
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
}

run_step() {
  local name="$1"
  local cmd="$2"
  local logfile="$EVIDENCE_DIR/${name}.log"

  log "START $name"
  {
    echo "# step=$name"
    echo "# command=$cmd"
    echo "# started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    bash -lc "$cmd"
  } > >(tee "$logfile") 2>&1

  local rc=${PIPESTATUS[0]}
  if [[ $rc -eq 0 ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "$name=PASS" >> "$SUMMARY"
    log "PASS  $name"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "$name=FAIL(rc=$rc)" >> "$SUMMARY"
    log "FAIL  $name rc=$rc"
  fi
}

find_challenge_reexec_entry() {
  local repo_root
  repo_root="$(cd "$ROOT/.." && pwd)"

  if [[ -n "${TRNM_CHALLENGE_REEXEC_ENTRY:-}" ]]; then
    if [[ -f "$TRNM_CHALLENGE_REEXEC_ENTRY" ]]; then
      echo "$TRNM_CHALLENGE_REEXEC_ENTRY"
      return 0
    fi
    return 1
  fi

  local candidates=(
    "$ROOT/scripts/run_challenge_reexec.sh"
    "$ROOT/scripts/check_challenge_reexec.sh"
    "$ROOT/scripts/run_challenge_reexecution.sh"
    "$ROOT/scripts/check_challenge_reexecution.sh"
    "$repo_root/scripts/challenge_reexec_e2e.sh"
    "$repo_root/scripts/run_challenge_reexec.sh"
  )

  local f
  for f in "${candidates[@]}"; do
    if [[ -f "$f" ]]; then
      echo "$f"
      return 0
    fi
  done

  return 1
}

{
  echo "local_release_evidence=evidence-$TS"
  echo "generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "workspace=$ROOT"
  echo "evidence_dir=$EVIDENCE_DIR"
  echo "truth_source=$REPO_ROOT/RELEASE_READINESS.md"
  echo "historical_evidence_only=true"
  echo "evidence_scope=local_rc_rehearsal_not_current_release_ready_claim"
  echo "env_tz=${TZ:-<unset>}"
  echo "env_lc_all=${LC_ALL:-<unset>}"
  echo "env_source_date_epoch=${SOURCE_DATE_EPOCH:-<unset>}"
  echo ""
  echo "steps:"
} > "$SUMMARY"

KEY_PACKAGES=(
  trnm-node
  trnm-worker-agent
  trnm-rpc
  trnm-pouw
  trnm-state
)

CARGO_TEST_CMD="cargo test"
for pkg in "${KEY_PACKAGES[@]}"; do
  CARGO_TEST_CMD+=" -p $pkg"
done
run_step "cargo_test_key_packages" "$CARGO_TEST_CMD"
run_step "check_request_tx_binding" "OUT_DIR='$EVIDENCE_DIR' ./scripts/check_request_tx_binding.sh"
run_step "run_request_fault_injection" "OUT_DIR='$EVIDENCE_DIR' ./scripts/run_request_fault_injection.sh"

if CHALLENGE_REEXEC_ENTRY="$(find_challenge_reexec_entry)"; then
  run_step "challenge_reexec" "OUT_DIR='$EVIDENCE_DIR' bash '$CHALLENGE_REEXEC_ENTRY'"
else
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "challenge_reexec=FAIL(entry_not_found)" >> "$SUMMARY"
  log "FAIL  challenge_reexec (entry not found)"
fi

rollback_cmd="rm -rf $(printf '%q' "$EVIDENCE_DIR")"

{
  echo ""
  echo "pass_count=$PASS_COUNT"
  echo "fail_count=$FAIL_COUNT"
  if [[ $FAIL_COUNT -eq 0 ]]; then
    echo "result=PASS"
  else
    echo "result=FAIL"
  fi
  echo "replay_command=env TZ=${TZ:-UTC} LC_ALL=${LC_ALL:-C} LANG=${LANG:-C} SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1704067200} CARGO_TERM_COLOR=${CARGO_TERM_COLOR:-never} RUST_BACKTRACE=${RUST_BACKTRACE:-1} CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-1} OUT_DIR='${OUT_DIR:-$BASE_OUT}' ./scripts/run_local_release_evidence.sh"
  echo "rollback_command=$rollback_cmd"
  echo "root_cause_hint=CI_FLAKE|ENV_DRIFT|DOC_DRIFT|MISSING_FIXTURE|NON_DETERMINISTIC_TEST"
} >> "$SUMMARY"

log "evidence_dir=$EVIDENCE_DIR"
log "summary=$SUMMARY"

if [[ $FAIL_COUNT -eq 0 ]]; then
  exit 0
else
  exit 1
fi
