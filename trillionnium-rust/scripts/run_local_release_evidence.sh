#!/usr/bin/env bash
set -u -o pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

replay_tz="UTC"
replay_lc_all="C"
replay_lang="C"
replay_source_date_epoch="1704067200"
replay_cargo_term_color="never"
replay_rust_backtrace="1"
replay_cargo_build_jobs="1"

export TZ="${TZ:-$replay_tz}"
export LC_ALL="${LC_ALL:-$replay_lc_all}"
export LANG="${LANG:-$replay_lang}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$replay_source_date_epoch}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-$replay_cargo_term_color}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-$replay_rust_backtrace}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$replay_cargo_build_jobs}"

REPO_ROOT="$(cd "$ROOT/.." && pwd)"
GIT_HEAD="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"

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
  echo "git_branch=$GIT_BRANCH"
  echo "git_head=$GIT_HEAD"
  echo "evidence_dir=$EVIDENCE_DIR"
  echo "truth_source=$REPO_ROOT/RELEASE_READINESS.md"
  echo "historical_evidence_only=true"
  echo "evidence_scope=local_rc_rehearsal_not_current_release_ready_claim"
  echo "env_tz=${TZ:-<unset>}"
  echo "env_lc_all=${LC_ALL:-<unset>}"
  echo "env_lang=${LANG:-<unset>}"
  echo "env_source_date_epoch=${SOURCE_DATE_EPOCH:-<unset>}"
  echo "env_cargo_term_color=${CARGO_TERM_COLOR:-<unset>}"
  echo "env_rust_backtrace=${RUST_BACKTRACE:-<unset>}"
  echo "env_cargo_build_jobs=${CARGO_BUILD_JOBS:-<unset>}"
  echo "replay_env_tz=$replay_tz"
  echo "replay_env_lc_all=$replay_lc_all"
  echo "replay_env_lang=$replay_lang"
  echo "replay_env_source_date_epoch=$replay_source_date_epoch"
  echo "replay_env_cargo_term_color=$replay_cargo_term_color"
  echo "replay_env_rust_backtrace=$replay_rust_backtrace"
  echo "replay_env_cargo_build_jobs=$replay_cargo_build_jobs"
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

CHALLENGE_REEXEC_ENTRY=""
if CHALLENGE_REEXEC_ENTRY="$(find_challenge_reexec_entry)"; then
  echo "challenge_reexec_entry=$CHALLENGE_REEXEC_ENTRY" >> "$SUMMARY"
  run_step "challenge_reexec" "OUT_DIR='$EVIDENCE_DIR' bash '$CHALLENGE_REEXEC_ENTRY'"
else
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "challenge_reexec=FAIL(entry_not_found)" >> "$SUMMARY"
  log "FAIL  challenge_reexec (entry not found)"
fi

rollback_cmd="rm -rf $(printf '%q' "$EVIDENCE_DIR")"
replay_out_dir="${OUT_DIR:-$BASE_OUT}"
replay_challenge_entry="${TRNM_CHALLENGE_REEXEC_ENTRY:-$CHALLENGE_REEXEC_ENTRY}"

{
  echo ""
  echo "pass_count=$PASS_COUNT"
  echo "fail_count=$FAIL_COUNT"
  if [[ $FAIL_COUNT -eq 0 ]]; then
    echo "result=PASS"
  else
    echo "result=FAIL"
  fi
  if [[ -n "$replay_challenge_entry" ]]; then
    echo "replay_command=env TZ=$replay_tz LC_ALL=$replay_lc_all LANG=$replay_lang SOURCE_DATE_EPOCH=$replay_source_date_epoch CARGO_TERM_COLOR=$replay_cargo_term_color RUST_BACKTRACE=$replay_rust_backtrace CARGO_BUILD_JOBS=$replay_cargo_build_jobs OUT_DIR='${replay_out_dir}' TRNM_CHALLENGE_REEXEC_ENTRY='${replay_challenge_entry}' ./scripts/run_local_release_evidence.sh"
  else
    echo "replay_command=env TZ=$replay_tz LC_ALL=$replay_lc_all LANG=$replay_lang SOURCE_DATE_EPOCH=$replay_source_date_epoch CARGO_TERM_COLOR=$replay_cargo_term_color RUST_BACKTRACE=$replay_rust_backtrace CARGO_BUILD_JOBS=$replay_cargo_build_jobs OUT_DIR='${replay_out_dir}' ./scripts/run_local_release_evidence.sh"
  fi
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
