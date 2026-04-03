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

normalize_branch_ref() {
  case "$1" in
    refs/*) printf '%s\n' "$1" ;;
    *) printf 'refs/heads/%s\n' "$1" ;;
  esac
}

export TZ="${TZ:-$replay_tz}"
export LC_ALL="${LC_ALL:-$replay_lc_all}"
export LANG="${LANG:-$replay_lang}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$replay_source_date_epoch}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-$replay_cargo_term_color}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-$replay_rust_backtrace}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$replay_cargo_build_jobs}"

REPO_ROOT="$(cd "$ROOT/.." && pwd)"
GIT_HEAD="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_BRANCH_RAW="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
if [[ "$GIT_BRANCH_RAW" == "HEAD" ]]; then
  GIT_BRANCH="<detached-HEAD>"
  GIT_HEAD_STATE="detached"
else
  GIT_BRANCH="$GIT_BRANCH_RAW"
  GIT_HEAD_STATE="attached"
fi
GIT_TOPLEVEL="$(git rev-parse --show-toplevel 2>/dev/null || echo unknown)"
GIT_STATUS_SHORT="$(git status --short 2>/dev/null || true)"
if [[ -z "$GIT_STATUS_SHORT" ]]; then
  GIT_STATUS_SUMMARY="clean"
else
  GIT_STATUS_SUMMARY="dirty"
fi
CURRENT_WORKTREE_ENTRY="$(git worktree list --porcelain 2>/dev/null | awk -v target="$GIT_TOPLEVEL" '
  BEGIN { in_match=0 }
  /^worktree / {
    in_match = ($2 == target)
  }
  in_match { print }
  in_match && /^$/ { exit }
' || true)"
if [[ -n "$CURRENT_WORKTREE_ENTRY" ]]; then
  CURRENT_WORKTREE_BRANCH_REF="$(printf '%s\n' "$CURRENT_WORKTREE_ENTRY" | awk '/^branch / { print $2; exit }')"
else
  CURRENT_WORKTREE_BRANCH_REF=""
fi
EXPECTED_BRANCH_REF_CANONICAL="${EXPECTED_BRANCH_REF:-}"
GIT_WORKTREE_BRANCH_REF_MATCH="unknown"
if [[ -n "$EXPECTED_BRANCH_REF_CANONICAL" ]]; then
  EXPECTED_BRANCH_REF_CANONICAL="$(normalize_branch_ref "$EXPECTED_BRANCH_REF_CANONICAL")"
  if [[ -n "$CURRENT_WORKTREE_BRANCH_REF" && "$CURRENT_WORKTREE_BRANCH_REF" == "$EXPECTED_BRANCH_REF_CANONICAL" ]]; then
    GIT_WORKTREE_BRANCH_REF_MATCH="true"
  else
    GIT_WORKTREE_BRANCH_REF_MATCH="false"
  fi
fi

lane_verify_command="<not-run>"
if [[ -n "${EXPECTED_WORKTREE_ROOT:-}" || -n "${EXPECTED_BRANCH_REF:-}" || -n "${EXPECTED_HEAD:-}" ]]; then
  [[ -n "${EXPECTED_WORKTREE_ROOT:-}" ]] || { echo "lane identity failed: EXPECTED_WORKTREE_ROOT is required when lane binding is enabled" >&2; exit 4; }
  [[ -n "${EXPECTED_BRANCH_REF:-}" ]] || { echo "lane identity failed: EXPECTED_BRANCH_REF is required when lane binding is enabled" >&2; exit 4; }
  EXPECTED_BRANCH_REF="$(normalize_branch_ref "$EXPECTED_BRANCH_REF")"
  lane_verify_args=(
    --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"
    --expected-branch-ref "$EXPECTED_BRANCH_REF"
  )
  if [[ -n "${EXPECTED_HEAD:-}" ]]; then
    lane_verify_args+=(--expected-head "$EXPECTED_HEAD")
  fi
  lane_verify_command="./scripts/v2/verify_lane_worktree.sh"
  for arg in "${lane_verify_args[@]}"; do
    printf -v quoted_arg '%q' "$arg"
    lane_verify_command+=" $quoted_arg"
  done
  ./scripts/v2/verify_lane_worktree.sh "${lane_verify_args[@]}"
fi

TS="$(date -u +%Y%m%d-%H%M%S)"
BASE_OUT_INPUT="${OUT_DIR:-$ROOT/run/health}"
mkdir -p "$BASE_OUT_INPUT"
BASE_OUT="$(cd "$BASE_OUT_INPUT" && pwd)"
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
  local tmpfile="$EVIDENCE_DIR/${name}.tmp"

  log "START $name"
  {
    echo "# step=$name"
    echo "# command=$cmd"
    echo "# started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    bash -lc "$cmd"
  } >"$tmpfile" 2>&1
  local rc=$?

  cat "$tmpfile" | tee "$logfile"
  rm -f "$tmpfile"

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

resolve_existing_path() {
  local target="$1"
  if [[ ! -f "$target" ]]; then
    return 1
  fi

  local dir base
  dir="$(cd "$(dirname "$target")" && pwd)"
  base="$(basename "$target")"
  printf '%s/%s\n' "$dir" "$base"
}

find_challenge_reexec_entry() {
  local repo_root
  repo_root="$(cd "$ROOT/.." && pwd)"

  if [[ -n "${TRNM_CHALLENGE_REEXEC_ENTRY:-}" ]]; then
    resolve_existing_path "$TRNM_CHALLENGE_REEXEC_ENTRY"
    return $?
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
    if resolve_existing_path "$f"; then
      return 0
    fi
  done

  return 1
}

{
  echo "local_release_evidence=evidence-$TS"
  echo "generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "workspace=$ROOT"
  echo "git_toplevel=$GIT_TOPLEVEL"
  echo "git_branch=$GIT_BRANCH"
  echo "git_head=$GIT_HEAD"
  echo "git_head_state=$GIT_HEAD_STATE"
  echo "git_status_summary=$GIT_STATUS_SUMMARY"
  echo "git_worktree_path=$GIT_TOPLEVEL"
  echo "git_worktree_branch_ref=${CURRENT_WORKTREE_BRANCH_REF:-<detached-or-unbound>}"
  echo "git_expected_worktree_branch_ref=${EXPECTED_BRANCH_REF_CANONICAL:-<unset>}"
  echo "git_worktree_branch_ref_match=$GIT_WORKTREE_BRANCH_REF_MATCH"
  echo "git_worktree_entry_begin"
  if [[ -n "$CURRENT_WORKTREE_ENTRY" ]]; then
    printf '%s\n' "$CURRENT_WORKTREE_ENTRY"
  fi
  echo "git_worktree_entry_end"
  echo "expected_worktree_root=${EXPECTED_WORKTREE_ROOT:-<unset>}"
  echo "expected_branch_ref=${EXPECTED_BRANCH_REF_CANONICAL:-<unset>}"
  echo "expected_head=${EXPECTED_HEAD:-<unset>}"
  echo "lane_verify_command=${lane_verify_command}"
  echo "git_status_short_begin"
  if [[ -n "$GIT_STATUS_SHORT" ]]; then
    printf '%s\n' "$GIT_STATUS_SHORT"
  fi
  echo "git_status_short_end"
  echo "evidence_dir=$EVIDENCE_DIR"
  echo "replay_out_dir=$BASE_OUT"
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
  echo "env_trnm_challenge_reexec_entry=${TRNM_CHALLENGE_REEXEC_ENTRY:-<unset>}"
  echo "replay_env_trnm_challenge_reexec_entry=<entry_not_found>"
  echo "challenge_reexec_entry=<entry_not_found>"
  echo ""
  echo "steps:"
} > "$SUMMARY"

KEY_PACKAGES="trnm-node trnm-worker-agent trnm-rpc trnm-pouw trnm-state"

CARGO_TEST_CMD="cargo test"
for pkg in $KEY_PACKAGES; do
  CARGO_TEST_CMD+=" -p $pkg"
done
run_step "cargo_test_key_packages" "$CARGO_TEST_CMD"
run_step "check_request_tx_binding" "OUT_DIR='$EVIDENCE_DIR' ./scripts/check_request_tx_binding.sh"
run_step "run_request_fault_injection" "OUT_DIR='$EVIDENCE_DIR' ./scripts/run_request_fault_injection.sh"

CHALLENGE_REEXEC_ENTRY=""
if CHALLENGE_REEXEC_ENTRY="$(find_challenge_reexec_entry)"; then
  summary_tmp="$EVIDENCE_DIR/summary.header.tmp"
  awk -v entry="$CHALLENGE_REEXEC_ENTRY" '
    /^replay_env_trnm_challenge_reexec_entry=<entry_not_found>$/ {
      print "replay_env_trnm_challenge_reexec_entry=" entry
      next
    }
    /^challenge_reexec_entry=<entry_not_found>$/ {
      print "challenge_reexec_entry=" entry
      next
    }
    { print }
  ' "$SUMMARY" > "$summary_tmp"
  mv "$summary_tmp" "$SUMMARY"
  run_step "challenge_reexec" "OUT_DIR='$EVIDENCE_DIR' bash '$CHALLENGE_REEXEC_ENTRY'"
else
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "challenge_reexec=FAIL(entry_not_found)" >> "$SUMMARY"
  log "FAIL  challenge_reexec (entry not found)"
fi

rollback_cmd="rm -rf $(printf '%q' "$EVIDENCE_DIR")"
replay_out_dir="$BASE_OUT"
replay_challenge_entry="$CHALLENGE_REEXEC_ENTRY"
replay_lane_binding=""
if [[ -n "${EXPECTED_WORKTREE_ROOT:-}" ]]; then
  replay_lane_binding+=" EXPECTED_WORKTREE_ROOT='${EXPECTED_WORKTREE_ROOT}'"
fi
if [[ -n "${EXPECTED_BRANCH_REF:-}" ]]; then
  replay_lane_binding+=" EXPECTED_BRANCH_REF='${EXPECTED_BRANCH_REF}'"
fi
if [[ -n "${EXPECTED_HEAD:-}" ]]; then
  replay_lane_binding+=" EXPECTED_HEAD='${EXPECTED_HEAD}'"
fi

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
    echo "replay_command=env TZ=$replay_tz LC_ALL=$replay_lc_all LANG=$replay_lang SOURCE_DATE_EPOCH=$replay_source_date_epoch CARGO_TERM_COLOR=$replay_cargo_term_color RUST_BACKTRACE=$replay_rust_backtrace CARGO_BUILD_JOBS=$replay_cargo_build_jobs OUT_DIR='${replay_out_dir}'${replay_lane_binding} TRNM_CHALLENGE_REEXEC_ENTRY='${replay_challenge_entry}' ./scripts/run_local_release_evidence.sh"
  else
    echo "replay_command=env TZ=$replay_tz LC_ALL=$replay_lc_all LANG=$replay_lang SOURCE_DATE_EPOCH=$replay_source_date_epoch CARGO_TERM_COLOR=$replay_cargo_term_color RUST_BACKTRACE=$replay_rust_backtrace CARGO_BUILD_JOBS=$replay_cargo_build_jobs OUT_DIR='${replay_out_dir}'${replay_lane_binding} ./scripts/run_local_release_evidence.sh"
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
