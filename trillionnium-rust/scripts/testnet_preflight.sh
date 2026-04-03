#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

export TZ="${TZ:-UTC}"
export LC_ALL="${LC_ALL:-C}"
export LANG="${LANG:-C}"

TS="$(date -u +%Y%m%d-%H%M%S)"
OUT_DIR="$ROOT/run/preflight"
LOG="$OUT_DIR/preflight-$TS.log"
SUMMARY="$OUT_DIR/go-no-go-$TS.txt"
mkdir -p "$OUT_DIR"

rollback_command_base="rm -f $(printf '%q' "$LOG") $(printf '%q' "$SUMMARY") $(printf '%q' "$OUT_DIR/preflight-latest.log") $(printf '%q' "$OUT_DIR/go-no-go-latest.txt") $(printf '%q' "$ROOT/run/parallel-sanity.log")"
rollback_command="$rollback_command_base"
replay_command="env TZ='${TZ}' LC_ALL='${LC_ALL}' LANG='${LANG}'"
if [ -n "${EXPECTED_WORKTREE_ROOT:-}" ]; then
  replay_command="$replay_command EXPECTED_WORKTREE_ROOT='${EXPECTED_WORKTREE_ROOT}'"
fi
normalize_branch_ref() {
  case "$1" in
    refs/*) printf '%s\n' "$1" ;;
    *) printf 'refs/heads/%s\n' "$1" ;;
  esac
}

if [ -n "${EXPECTED_BRANCH_REF:-}" ]; then
  EXPECTED_BRANCH_REF="$(normalize_branch_ref "$EXPECTED_BRANCH_REF")"
  replay_command="$replay_command EXPECTED_BRANCH_REF='${EXPECTED_BRANCH_REF}'"
fi
if [ -n "${EXPECTED_HEAD:-}" ]; then
  replay_command="$replay_command EXPECTED_HEAD='${EXPECTED_HEAD}'"
fi
replay_command="$replay_command ./scripts/testnet_preflight.sh"
lane_verify_command=""

GIT_HEAD="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_BRANCH_RAW="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
if [ "$GIT_BRANCH_RAW" = "HEAD" ]; then
  GIT_BRANCH="<detached-HEAD>"
  GIT_HEAD_STATE="detached"
else
  GIT_BRANCH="$GIT_BRANCH_RAW"
  GIT_HEAD_STATE="attached"
fi
GIT_TOPLEVEL="$(git rev-parse --show-toplevel 2>/dev/null || echo unknown)"
GIT_STATUS_SHORT="$(git status --short 2>/dev/null || true)"
if [ -z "$GIT_STATUS_SHORT" ]; then
  GIT_STATUS_SUMMARY="clean"
else
  GIT_STATUS_SUMMARY="dirty"
fi
CURRENT_WORKTREE_ENTRY="$(git worktree list --porcelain 2>/dev/null | awk -v target="$GIT_TOPLEVEL" '
  BEGIN { in_match=0 }
  /^worktree / {
    path = substr($0, length("worktree ") + 1)
    in_match = (path == target)
  }
  in_match { print }
  in_match && /^$/ { exit }
' || true)"
if [ -n "$CURRENT_WORKTREE_ENTRY" ]; then
  CURRENT_WORKTREE_BRANCH_REF="$(printf '%s\n' "$CURRENT_WORKTREE_ENTRY" | awk '/^branch / { print $2; exit }')"
else
  CURRENT_WORKTREE_BRANCH_REF=""
fi
EXPECTED_BRANCH_REF_CANONICAL="${EXPECTED_BRANCH_REF:-}"
GIT_WORKTREE_BRANCH_REF_MATCH="unknown"
if [ -n "$EXPECTED_BRANCH_REF_CANONICAL" ]; then
  EXPECTED_BRANCH_REF_CANONICAL="$(normalize_branch_ref "$EXPECTED_BRANCH_REF_CANONICAL")"
  if [ -n "$CURRENT_WORKTREE_BRANCH_REF" ] && [ "$CURRENT_WORKTREE_BRANCH_REF" = "$EXPECTED_BRANCH_REF_CANONICAL" ]; then
    GIT_WORKTREE_BRANCH_REF_MATCH="true"
  else
    GIT_WORKTREE_BRANCH_REF_MATCH="false"
  fi
fi

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

if [ "$GIT_HEAD_STATE" = "attached" ] && [ -z "$CURRENT_WORKTREE_BRANCH_REF" ]; then
  log "preflight failed: attached HEAD is missing git worktree branch binding"
  exit 10
fi

if [ "$GIT_HEAD_STATE" = "attached" ] && [ -n "$CURRENT_WORKTREE_BRANCH_REF" ]; then
  CURRENT_WORKTREE_BRANCH_NAME="${CURRENT_WORKTREE_BRANCH_REF#refs/heads/}"
  if [ "$CURRENT_WORKTREE_BRANCH_NAME" != "$GIT_BRANCH" ]; then
    log "preflight failed: git branch '$GIT_BRANCH' does not match git worktree branch binding '$CURRENT_WORKTREE_BRANCH_REF'"
    exit 11
  fi
fi

log "start testnet preflight"
log "git_toplevel=$GIT_TOPLEVEL git_branch=$GIT_BRANCH git_head=$GIT_HEAD git_head_state=$GIT_HEAD_STATE git_worktree_branch_ref=${CURRENT_WORKTREE_BRANCH_REF:-<detached-or-unbound>} git_expected_worktree_branch_ref=${EXPECTED_BRANCH_REF_CANONICAL:-<unset>} git_worktree_branch_ref_match=$GIT_WORKTREE_BRANCH_REF_MATCH git_status_summary=$GIT_STATUS_SUMMARY"

if [ -n "${EXPECTED_WORKTREE_ROOT:-}" ] || [ -n "${EXPECTED_BRANCH_REF:-}" ] || [ -n "${EXPECTED_HEAD:-}" ]; then
  [ -n "${EXPECTED_WORKTREE_ROOT:-}" ] || { log "lane identity failed: EXPECTED_WORKTREE_ROOT is required when lane binding is enabled"; exit 4; }
  [ -n "${EXPECTED_BRANCH_REF:-}" ] || { log "lane identity failed: EXPECTED_BRANCH_REF is required when lane binding is enabled"; exit 4; }
  log "verify lane-bound worktree identity"
  lane_verify_args=(
    --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"
    --expected-branch-ref "$EXPECTED_BRANCH_REF"
  )
  if [ -n "${EXPECTED_HEAD:-}" ]; then
    lane_verify_args+=(--expected-head "$EXPECTED_HEAD")
  fi
  lane_verify_command="./scripts/v2/verify_lane_worktree.sh"
  for arg in "${lane_verify_args[@]}"; do
    printf -v quoted_arg '%q' "$arg"
    lane_verify_command+=" $quoted_arg"
  done
  log "lane_verify_command=$lane_verify_command"
  ./scripts/v2/verify_lane_worktree.sh "${lane_verify_args[@]}" | tee -a "$LOG"
fi

if [ "$GIT_STATUS_SUMMARY" != "clean" ]; then
  log "preflight failed: dirty worktree (git status --short must be empty for clean-tree rehearsal)"
  exit 5
fi

log "check shell syntax"
bash -n ./scripts/testnet_preflight.sh
bash -n ./scripts/check_bft_restart_recovery.sh
bash -n ./scripts/check_bft_4node_smoke.sh
bash -n ./scripts/run_consensus_fault_matrix.sh
bash -n ./scripts/run_consensus_security_matrix.sh
bash -n ./scripts/check_bft_round_change.sh
bash -n ./scripts/check_bft_message_auth.sh
bash -n ./scripts/check_event_fields.sh
bash -n ./scripts/check_event_replay_smoke.sh
bash -n ./scripts/check_request_tx_binding.sh
bash -n ./scripts/run_request_fault_injection.sh
bash -n ./scripts/release_rc.sh
bash -n ./scripts/run_local_release_evidence.sh
bash -n ./scripts/run_industrial_readiness_check.sh
bash -n ./scripts/check_nightly_green_streak.sh
bash -n ./scripts/check_parallel_flaky.sh
bash -n ./scripts/run_phasea_fault_injection_suite.sh
bash -n ./scripts/enforce_ci_thresholds.sh
bash -n ./scripts/v2/verify_lane_worktree.sh
bash -n ./scripts/v2/extract_release_handoff_fields.sh
bash -n ./scripts/devnet_up.sh
bash -n ./scripts/devnet_down.sh
bash -n ./scripts/audit_state_roots.sh
bash -n ./scripts/run_bench_matrix.sh
bash -n ./scripts/run_bench_mixed_matrix.sh

log "check script prerequisites"
command -v python3 >/dev/null
python3 -m py_compile ./scripts/executor_profile_report.py
python3 -m py_compile ./scripts/render_benchmark_closeout.py
python3 -m py_compile ./scripts/validate_benchmark_closeout.py

log "check rust toolchain"
command -v cargo >/dev/null
cargo --version | tee -a "$LOG"

log "check configs"
for f in configs/node1.toml configs/node2.toml configs/node3.toml configs/node4.toml; do
  [[ -f "$f" ]] || { echo "missing $f" | tee -a "$LOG"; exit 1; }
done

log "workspace tests"
cargo test --workspace | tee -a "$LOG"

log "single-node parallel sanity"
cargo run -q -p trnm-node -- \
  --config configs/node1.toml \
  --block-ms 5 \
  --max-blocks 6 \
  --demo-tasks 8 \
  --demo-keys 3 \
  --parallel-workers 4 | tee "$ROOT/run/parallel-sanity.log" | tee -a "$LOG"

if grep -E '\[tx\] apply_error|rollback=true' "$ROOT/run/parallel-sanity.log" >/dev/null; then
  log "parallel sanity failed: apply_error/rollback detected"
  exit 2
fi

if ! grep -q '^\[consensus\] finality_p50_ms=' "$ROOT/run/parallel-sanity.log"; then
  log "parallel sanity failed: missing consensus finality metric"
  exit 3
fi

if ! grep -q 'bft_round_change_backoff_total_ms=' "$ROOT/run/parallel-sanity.log"; then
  log "parallel sanity failed: missing consensus recovery metric (bft_round_change_backoff_total_ms)"
  exit 3
fi

log "bft restart recovery drill"
RECOVERY_RUNS="${RECOVERY_RUNS:-1}"
case "$RECOVERY_RUNS" in
  ''|*[!0-9]*)
    log "recovery drill failed: RECOVERY_RUNS must be a positive integer (got '$RECOVERY_RUNS')"
    exit 12
    ;;
esac
if [ "$RECOVERY_RUNS" -lt 1 ]; then
  log "recovery drill failed: RECOVERY_RUNS must be >= 1 (got '$RECOVERY_RUNS')"
  exit 12
fi
replay_command="$replay_command RECOVERY_RUNS='${RECOVERY_RUNS}'"
recovery_env=(RUNS="$RECOVERY_RUNS")
if [ -n "${EXPECTED_WORKTREE_ROOT:-}" ]; then
  recovery_env+=(EXPECTED_WORKTREE_ROOT="$EXPECTED_WORKTREE_ROOT")
fi
if [ -n "${EXPECTED_BRANCH_REF:-}" ]; then
  recovery_env+=(EXPECTED_BRANCH_REF="$EXPECTED_BRANCH_REF")
fi
if [ -n "${EXPECTED_HEAD:-}" ]; then
  recovery_env+=(EXPECTED_HEAD="$EXPECTED_HEAD")
fi
RECOVERY_REPORT="$(env "${recovery_env[@]}" ./scripts/check_bft_restart_recovery.sh | tee -a "$LOG" | tail -n 1 | sed 's/^.*: //')"
if [ -z "$RECOVERY_REPORT" ] || [ ! -f "$RECOVERY_REPORT" ]; then
  log "recovery drill failed: missing restart recovery report"
  exit 12
fi
RECOVERY_REPORT_DIR="$(cd "$(dirname "$RECOVERY_REPORT")" && pwd -P)"
RECOVERY_REPORT_CANON="$RECOVERY_REPORT_DIR/$(basename "$RECOVERY_REPORT")"
case "$RECOVERY_REPORT_CANON" in
  "$ROOT/run/"*) ;;
  *)
    log "recovery drill failed: restart recovery report escaped run/ ($RECOVERY_REPORT_CANON)"
    exit 12
    ;;
esac
if ! grep -q '^status=PASS$' "$RECOVERY_REPORT"; then
  log "recovery drill failed: restart recovery report is not PASS ($RECOVERY_REPORT)"
  exit 12
fi
RECOVERY_REPLAY_COMMAND="$(awk -F= '/^replay_command=/ { sub(/^replay_command=/, ""); print; exit }' "$RECOVERY_REPORT")"
if [ -z "$RECOVERY_REPLAY_COMMAND" ]; then
  log "recovery drill failed: missing replay_command in restart recovery report ($RECOVERY_REPORT)"
  exit 12
fi
RECOVERY_ROLLBACK_COMMAND="$(awk -F= '/^rollback_command=/ { sub(/^rollback_command=/, ""); print; exit }' "$RECOVERY_REPORT")"
if [ -z "$RECOVERY_ROLLBACK_COMMAND" ]; then
  log "recovery drill failed: missing rollback_command in restart recovery report ($RECOVERY_REPORT)"
  exit 12
fi
rollback_command="$rollback_command && $RECOVERY_ROLLBACK_COMMAND"

cleanup_devnet() {
  if [ "${DEVNET_STARTED:-0}" -eq 1 ]; then
    ./scripts/devnet_down.sh | tee -a "$LOG" || true
    DEVNET_STARTED=0
  fi
}

log "devnet + audit"
DEVNET_STARTED=0
trap cleanup_devnet EXIT
./scripts/devnet_up.sh | tee -a "$LOG"
DEVNET_STARTED=1
sleep 12
./scripts/audit_state_roots.sh | tee -a "$LOG"
cleanup_devnet
trap - EXIT

latest_audit=$(find run/audit -maxdepth 1 -type f -name 'state-root-audit-*.txt' -print 2>/dev/null | sort | tail -n 1)
if [ -z "$latest_audit" ]; then
  log "audit failed: missing state-root audit report under run/audit"
  exit 6
fi
grep -q 'summary ok=true mismatch=0 missing=0' "$latest_audit"
log "audit pass: $latest_audit"

log "quick benchmark matrix"
TXS=5000 ./scripts/run_bench_matrix.sh | tee -a "$LOG"
TXS=5000 ./scripts/run_bench_mixed_matrix.sh | tee -a "$LOG"
./scripts/executor_profile_report.py | tee -a "$LOG"

latest_bench=$(find run/bench -maxdepth 1 -type f -name 'bench-matrix-*.txt' -print 2>/dev/null | sort | tail -n 1)
if [ -z "$latest_bench" ]; then
  log "benchmark failed: missing classic bench matrix report under run/bench"
  exit 7
fi
latest_mixed=$(find run/bench -maxdepth 1 -type f -name 'bench-mixed-matrix-*.txt' -print 2>/dev/null | sort | tail -n 1)
if [ -z "$latest_mixed" ]; then
  log "benchmark failed: missing mixed bench matrix report under run/bench"
  exit 8
fi
latest_profile=$(find run/bench -maxdepth 1 -type f -name 'executor-profile-summary-*.txt' -print 2>/dev/null | sort | tail -n 1)
if [ -z "$latest_profile" ]; then
  log "benchmark failed: missing executor profile summary under run/bench"
  exit 9
fi

rollback_command="$rollback_command && rm -f $(printf '%q' "$latest_audit") $(printf '%q' "$latest_bench") $(printf '%q' "$latest_mixed") $(printf '%q' "$latest_profile")"

cat > "$SUMMARY" <<EOF
rust_l1_testnet_preflight
status=GO
result=GO
timestamp=$TS
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
truth_source=$ROOT/RELEASE_READINESS.md
log=$LOG
git_toplevel=$GIT_TOPLEVEL
git_branch=$GIT_BRANCH
git_head=$GIT_HEAD
git_head_state=$GIT_HEAD_STATE
git_status_summary=$GIT_STATUS_SUMMARY
git_worktree_path=$GIT_TOPLEVEL
git_worktree_branch_ref=${CURRENT_WORKTREE_BRANCH_REF:-<detached-or-unbound>}
git_expected_worktree_branch_ref=${EXPECTED_BRANCH_REF_CANONICAL:-<unset>}
git_worktree_branch_ref_match=$GIT_WORKTREE_BRANCH_REF_MATCH
expected_worktree_root=${EXPECTED_WORKTREE_ROOT:-<unset>}
expected_branch_ref=${EXPECTED_BRANCH_REF_CANONICAL:-<unset>}
expected_head=${EXPECTED_HEAD:-<unset>}
git_worktree_entry_begin
$CURRENT_WORKTREE_ENTRY
git_worktree_entry_end
git_status_short_begin
$GIT_STATUS_SHORT
git_status_short_end
audit=$latest_audit
bench_classic=$latest_bench
bench_mixed=$latest_mixed
executor_profile=$latest_profile
recovery_runs=$RECOVERY_RUNS
recovery_report=$RECOVERY_REPORT
recovery_replay_command=$RECOVERY_REPLAY_COMMAND
replay_command=$replay_command
lane_verify_command=${lane_verify_command:-<not-run>}
rollback_command=$rollback_command
EOF

cp -f "$SUMMARY" "$OUT_DIR/go-no-go-latest.txt"
cp -f "$LOG" "$OUT_DIR/preflight-latest.log"

log "[OK] testnet preflight passed"
log "summary: $SUMMARY"
log "log: $LOG"
echo "$SUMMARY"