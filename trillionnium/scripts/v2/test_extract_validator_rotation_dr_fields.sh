#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/v2/extract_validator_rotation_dr_fields.sh"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

REPO="$TMPDIR/repo"
mkdir -p "$REPO/run"
cd "$REPO"

git init -q
mkdir -p configs
touch configs/node1.toml
git add configs/node1.toml
git commit -qm 'init'

WORKTREE_ROOT="$(pwd -P)"
BRANCH_REF="refs/heads/lane/mn05-operator-dr-rotation-lifecycle"
HEAD_SHA="$(git rev-parse HEAD)"
REPORT_PATH="$REPO/run/bft-restart-recovery-20260404.txt"
REPORT_PATH_CANONICAL="$(cd "$(dirname "$REPORT_PATH")" && pwd -P)/$(basename "$REPORT_PATH")"

cat >"$REPORT_PATH" <<EOF
generated_at=2026-04-04T11:59:00Z
config_path=$WORKTREE_ROOT/configs/node1.toml
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_branch=lane/mn05-operator-dr-rotation-lifecycle
git_head=$HEAD_SHA
git_status_summary=clean
rollback_command=git reset --hard $HEAD_SHA
replay_command=./scripts/check_bft_restart_recovery.sh --config $WORKTREE_ROOT/configs/node1.toml
status=PASS
expected_worktree_root=$WORKTREE_ROOT
expected_branch_ref=lane/mn05-operator-dr-rotation-lifecycle
lane_verify_command=./scripts/v2/verify_lane_worktree.sh --expected-worktree-root $WORKTREE_ROOT --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle --expected-head $HEAD_SHA
expected_head=$HEAD_SHA
EOF

bash "$SCRIPT" --report-path "$REPORT_PATH" >"$TMPDIR/out.txt"
grep -q "^dr_summary_path=$REPORT_PATH_CANONICAL$" "$TMPDIR/out.txt"
grep -q "^expected_branch_ref=lane/mn05-operator-dr-rotation-lifecycle$" "$TMPDIR/out.txt"
grep -q "^lane_verify_command=./scripts/v2/verify_lane_worktree.sh --expected-worktree-root $WORKTREE_ROOT --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle --expected-head $HEAD_SHA$" "$TMPDIR/out.txt"

cat >"$REPORT_PATH" <<EOF
generated_at=2026-04-04T11:59:00Z
config_path=$WORKTREE_ROOT/configs/node1.toml
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_branch=lane/mn05-operator-dr-rotation-lifecycle
git_head=$HEAD_SHA
git_status_summary=clean
rollback_command=git reset --hard $HEAD_SHA
replay_command=./scripts/check_bft_restart_recovery.sh --config $WORKTREE_ROOT/configs/node1.toml
status=PASS
expected_worktree_root=$WORKTREE_ROOT
expected_branch_ref=$BRANCH_REF
lane_verify_command=./scripts/v2/verify_lane_worktree.sh --expected-worktree-root $WORKTREE_ROOT --expected-branch-ref $BRANCH_REF --expected-head $HEAD_SHA
expected_head=$HEAD_SHA
EOF

bash "$SCRIPT" --report-path "$REPORT_PATH" >"$TMPDIR/out.txt"
grep -q "^expected_branch_ref=$BRANCH_REF$" "$TMPDIR/out.txt"
grep -q "^lane_verify_command=./scripts/v2/verify_lane_worktree.sh --expected-worktree-root $WORKTREE_ROOT --expected-branch-ref $BRANCH_REF --expected-head $HEAD_SHA$" "$TMPDIR/out.txt"

cat >"$REPORT_PATH" <<EOF
generated_at=2026-04-04T11:59:00Z
config_path=$WORKTREE_ROOT/configs/node1.toml
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_branch=lane/mn05-operator-dr-rotation-lifecycle
git_head=$HEAD_SHA
git_status_summary=clean
rollback_command=git reset --hard $HEAD_SHA
replay_command=./scripts/check_bft_restart_recovery.sh --config $WORKTREE_ROOT/configs/node1.toml
status=PASS
expected_worktree_root=$WORKTREE_ROOT
expected_branch_ref=lane/mn05-operator-dr-rotation-lifecycle
lane_verify_command=./scripts/v2/verify_lane_worktree.sh --expected-worktree-root $WORKTREE_ROOT --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle
expected_head=$HEAD_SHA
EOF

if bash "$SCRIPT" --report-path "$REPORT_PATH" >"$TMPDIR/out.txt" 2>"$TMPDIR/err.txt"; then
  echo "expected missing --expected-head lane verify command to fail" >&2
  exit 1
fi
grep -q "lane_verify_command missing --expected-head $HEAD_SHA in $REPORT_PATH_CANONICAL" "$TMPDIR/err.txt"

cat >"$REPORT_PATH" <<EOF
generated_at=2026-04-04T11:59:00Z
config_path=$WORKTREE_ROOT/configs/node1.toml
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_branch=lane/mn05-operator-dr-rotation-lifecycle
git_head=$HEAD_SHA
git_status_summary=clean
rollback_command=git reset --hard $HEAD_SHA
replay_command=./scripts/check_bft_restart_recovery.sh --config $WORKTREE_ROOT/configs/node1.toml
status=PASS
expected_worktree_root=$WORKTREE_ROOT
expected_branch_ref=lane/mn05-operator-dr-rotation-lifecycle
lane_verify_command=./scripts/v2/verify_lane_worktree.sh --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle --expected-head $HEAD_SHA
expected_head=$HEAD_SHA
EOF

if bash "$SCRIPT" --report-path "$REPORT_PATH" >"$TMPDIR/out.txt" 2>"$TMPDIR/err.txt"; then
  echo "expected missing --expected-worktree-root lane verify command to fail" >&2
  exit 1
fi
grep -q "lane_verify_command missing --expected-worktree-root $WORKTREE_ROOT in $REPORT_PATH_CANONICAL" "$TMPDIR/err.txt"

cat >"$REPORT_PATH" <<EOF
generated_at=2026-04-04T11:59:00Z
config_path=$WORKTREE_ROOT/configs/node1.toml
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_branch=lane/mn05-operator-dr-rotation-lifecycle
git_head=$HEAD_SHA
git_status_summary=clean
rollback_command=git reset --hard $HEAD_SHA
replay_command=./scripts/check_bft_restart_recovery.sh --config $WORKTREE_ROOT/configs/node1.toml
status=PASS
expected_worktree_root=$WORKTREE_ROOT
expected_branch_ref=lane/mn05-operator-dr-rotation-lifecycle
lane_verify_command=./scripts/v2/verify_lane_worktree.sh --expected-worktree-root $WORKTREE_ROOT --expected-head $HEAD_SHA
expected_head=$HEAD_SHA
EOF

if bash "$SCRIPT" --report-path "$REPORT_PATH" >"$TMPDIR/out.txt" 2>"$TMPDIR/err.txt"; then
  echo "expected missing --expected-branch-ref lane verify command to fail" >&2
  exit 1
fi
grep -q "lane_verify_command missing --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle in $REPORT_PATH_CANONICAL" "$TMPDIR/err.txt"

OUTSIDE_ROOT="$TMPDIR/outside"
mkdir -p "$OUTSIDE_ROOT/run"
OUTSIDE_REPORT_PATH="$OUTSIDE_ROOT/run/$(basename "$REPORT_PATH")"
OUTSIDE_REPORT_PATH_CANONICAL="$(cd "$(dirname "$OUTSIDE_REPORT_PATH")" && pwd -P)/$(basename "$OUTSIDE_REPORT_PATH")"
cat >"$OUTSIDE_REPORT_PATH" <<EOF
generated_at=2026-04-04T11:59:00Z
config_path=$WORKTREE_ROOT/configs/node1.toml
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_branch=lane/mn05-operator-dr-rotation-lifecycle
git_head=$HEAD_SHA
git_status_summary=clean
rollback_command=git reset --hard $HEAD_SHA
replay_command=./scripts/check_bft_restart_recovery.sh --config $WORKTREE_ROOT/configs/node1.toml
status=PASS
expected_worktree_root=$WORKTREE_ROOT
expected_branch_ref=lane/mn05-operator-dr-rotation-lifecycle
lane_verify_command=./scripts/v2/verify_lane_worktree.sh --expected-worktree-root $WORKTREE_ROOT --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle --expected-head $HEAD_SHA
expected_head=$HEAD_SHA
EOF

if bash "$SCRIPT" --report-path "$OUTSIDE_REPORT_PATH" >"$TMPDIR/out.txt" 2>"$TMPDIR/err.txt"; then
  echo "expected report outside current worktree run/ to fail" >&2
  exit 1
fi
grep -q "recovery report must live under current worktree run/: $OUTSIDE_REPORT_PATH_CANONICAL" "$TMPDIR/err.txt"

cat >"$REPORT_PATH" <<EOF
generated_at=2026-04-04T11:59:00Z
config_path=$WORKTREE_ROOT/configs/node1.toml
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_branch=lane/mn05-operator-dr-rotation-lifecycle
git_head=$HEAD_SHA
git_status_summary=clean
rollback_command=git reset --hard $HEAD_SHA
replay_command=./scripts/check_bft_restart_recovery.sh --config $WORKTREE_ROOT/configs/node1.toml
status=PASS
expected_worktree_root=$WORKTREE_ROOT
lane_verify_command=./scripts/v2/verify_lane_worktree.sh --expected-worktree-root $WORKTREE_ROOT
EOF

if bash "$SCRIPT" --report-path "$REPORT_PATH" >"$TMPDIR/out.txt" 2>"$TMPDIR/err.txt"; then
  echo "expected incomplete lane binding to fail" >&2
  exit 1
fi
grep -q "incomplete lane binding in $REPORT_PATH_CANONICAL: missing expected_branch_ref" "$TMPDIR/err.txt"

cat >"$REPORT_PATH" <<EOF
generated_at=2026-04-04T11:59:00Z
config_path=$WORKTREE_ROOT/configs/node1.toml
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_branch=lane/mn05-operator-dr-rotation-lifecycle
git_head=$HEAD_SHA
git_status_summary=clean
rollback_command=git reset --hard $HEAD_SHA
replay_command=./scripts/check_bft_restart_recovery.sh --config $WORKTREE_ROOT/configs/node1.toml
status=PASS
expected_worktree_root=$WORKTREE_ROOT
expected_branch_ref=lane/mn05-operator-dr-rotation-lifecycle
EOF

if bash "$SCRIPT" --report-path "$REPORT_PATH" >"$TMPDIR/out.txt" 2>"$TMPDIR/err.txt"; then
  echo "expected missing lane_verify_command to fail" >&2
  exit 1
fi
grep -q "lane_verify_command missing --expected-worktree-root $WORKTREE_ROOT in $REPORT_PATH_CANONICAL" "$TMPDIR/err.txt"

echo "PASS"
