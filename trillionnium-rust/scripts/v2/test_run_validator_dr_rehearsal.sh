#!/usr/bin/env bash
set -euo pipefail

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

ROOT="$TMPDIR/repo"
mkdir -p "$ROOT/scripts/v2" "$ROOT/run"

cp "$(cd "$(dirname "$0")/../.." && pwd)/scripts/v2/run_validator_dr_rehearsal.sh" \
  "$ROOT/scripts/v2/run_validator_dr_rehearsal.sh"
chmod +x "$ROOT/scripts/v2/run_validator_dr_rehearsal.sh"

cat >"$ROOT/scripts/v2/verify_lane_worktree.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >"$TRNM_VERIFY_ARGS_LOG"
EOF
chmod +x "$ROOT/scripts/v2/verify_lane_worktree.sh"

cat >"$ROOT/scripts/check_bft_restart_recovery.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'EXPECTED_WORKTREE_ROOT=%s\n' "${EXPECTED_WORKTREE_ROOT-}" >"$TRNM_RECOVERY_ENV_LOG"
printf 'EXPECTED_BRANCH_REF=%s\n' "${EXPECTED_BRANCH_REF-}" >>"$TRNM_RECOVERY_ENV_LOG"
printf 'EXPECTED_HEAD=%s\n' "${EXPECTED_HEAD-}" >>"$TRNM_RECOVERY_ENV_LOG"
printf '[OK] bft restart recovery passed: %s\n' "$TRNM_REPORT_PATH"
EOF
chmod +x "$ROOT/scripts/check_bft_restart_recovery.sh"

cat >"$ROOT/scripts/v2/extract_validator_rotation_dr_fields.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >"$TRNM_EXTRACT_ARGS_LOG"
printf 'dr_summary_path=%s\n' "$TRNM_REPORT_PATH"
printf 'expected_head=%s\n' "$TRNM_EXPECTED_HEAD"
EOF
chmod +x "$ROOT/scripts/v2/extract_validator_rotation_dr_fields.sh"

EXPECTED_WORKTREE_ROOT="/Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle"
EXPECTED_BRANCH_REF="lane/mn05-operator-dr-rotation-lifecycle"
EXPECTED_HEAD="0123456789abcdef0123456789abcdef01234567"
REPORT_PATH="$ROOT/run/bft-restart-recovery-20260404T224500Z.txt"

export TRNM_VERIFY_ARGS_LOG="$TMPDIR/verify-args.log"
export TRNM_RECOVERY_ENV_LOG="$TMPDIR/recovery-env.log"
export TRNM_EXTRACT_ARGS_LOG="$TMPDIR/extract-args.log"
export TRNM_REPORT_PATH="$REPORT_PATH"
export TRNM_EXPECTED_HEAD="$EXPECTED_HEAD"

OUTPUT="$({
  cd "$ROOT"
  bash ./scripts/v2/run_validator_dr_rehearsal.sh \
    --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
    --expected-branch-ref "$EXPECTED_BRANCH_REF" \
    --expected-head "$EXPECTED_HEAD"
} 2>"$TMPDIR/stderr.log")"

grep -q -- "--expected-worktree-root $EXPECTED_WORKTREE_ROOT --expected-branch-ref $EXPECTED_BRANCH_REF --expected-head $EXPECTED_HEAD" "$TRNM_VERIFY_ARGS_LOG"
grep -q "^EXPECTED_WORKTREE_ROOT=$EXPECTED_WORKTREE_ROOT$" "$TRNM_RECOVERY_ENV_LOG"
grep -q "^EXPECTED_BRANCH_REF=$EXPECTED_BRANCH_REF$" "$TRNM_RECOVERY_ENV_LOG"
grep -q "^EXPECTED_HEAD=$EXPECTED_HEAD$" "$TRNM_RECOVERY_ENV_LOG"
grep -q -- "--report-path $REPORT_PATH --expected-worktree-root $EXPECTED_WORKTREE_ROOT --expected-branch-ref $EXPECTED_BRANCH_REF --expected-head $EXPECTED_HEAD" "$TRNM_EXTRACT_ARGS_LOG"
printf '%s\n' "$OUTPUT" | grep -q "^dr_summary_path=$REPORT_PATH$"
printf '%s\n' "$OUTPUT" | grep -q "^expected_head=$EXPECTED_HEAD$"
grep -q "^\[OK\] bft restart recovery passed: $REPORT_PATH$" "$TMPDIR/stderr.log"

echo "PASS"
