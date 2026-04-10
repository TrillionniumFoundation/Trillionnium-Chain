#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/v2/extract_release_handoff_fields.sh"
SUFFIX="test-extract-release-handoff-fields-$$"
SUMMARY_DIR="$ROOT/run/health/evidence-$SUFFIX"
MANIFEST_DIR="$ROOT/release/rc-$SUFFIX"
PREFLIGHT_PATH="$ROOT/run/preflight/go-no-go-latest.txt"
BACKUP_PREFLIGHT=""
cleanup() {
  rm -rf "$SUMMARY_DIR" "$MANIFEST_DIR"
  if [ -n "$BACKUP_PREFLIGHT" ] && [ -f "$BACKUP_PREFLIGHT" ]; then
    mv "$BACKUP_PREFLIGHT" "$PREFLIGHT_PATH"
  else
    rm -f "$PREFLIGHT_PATH"
  fi
}
trap cleanup EXIT

mkdir -p "$SUMMARY_DIR" "$MANIFEST_DIR" "$ROOT/run/preflight"
if [ -f "$PREFLIGHT_PATH" ]; then
  BACKUP_PREFLIGHT="$PREFLIGHT_PATH.$$.bak"
  cp "$PREFLIGHT_PATH" "$BACKUP_PREFLIGHT"
fi

cd "$ROOT"
WORKTREE_ROOT="$(pwd -P)"
BRANCH_SHORT="lane/mn12-alerting-dashboard-incident-sre"
BRANCH_REF="refs/heads/$BRANCH_SHORT"
HEAD_SHA="$(git rev-parse HEAD)"
SUMMARY_PATH="$SUMMARY_DIR/summary.txt"
MANIFEST_PATH="$MANIFEST_DIR/manifest.txt"
SUMMARY_PATH_CANONICAL="$(cd "$(dirname "$SUMMARY_PATH")" && pwd -P)/$(basename "$SUMMARY_PATH")"
MANIFEST_PATH_CANONICAL="$(cd "$(dirname "$MANIFEST_PATH")" && pwd -P)/$(basename "$MANIFEST_PATH")"
PREFLIGHT_PATH_CANONICAL="$(cd "$(dirname "$PREFLIGHT_PATH")" && pwd -P)/$(basename "$PREFLIGHT_PATH")"
ROLLBACK_CMD="git reset --hard $HEAD_SHA"
REPLAY_CMD="./scripts/run_local_release_evidence.sh --expected-worktree-root $WORKTREE_ROOT --expected-branch-ref $BRANCH_SHORT"
CHALLENGE_REEXEC_ENTRY="trillionnium/challenges/example.json"
REPLAY_ENV_ENTRY="TRNM_CHALLENGE_REEXEC_ENTRY=$CHALLENGE_REEXEC_ENTRY"
TMP_OUT="$(mktemp)"
trap 'rm -f "$TMP_OUT"; cleanup' EXIT

cat >"$SUMMARY_PATH" <<EOF
summary_path=$SUMMARY_PATH_CANONICAL
generated_at=2026-04-11T00:00:00Z
git_toplevel=$WORKTREE_ROOT
git_branch=$BRANCH_SHORT
git_head=$HEAD_SHA
git_head_state=attached
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_expected_worktree_branch_ref=$BRANCH_REF
git_worktree_branch_ref_match=true
git_status_summary=clean
truth_source=$WORKTREE_ROOT/RELEASE_READINESS.md
historical_evidence_only=false
evidence_scope=local_rc_rehearsal_not_current_release_ready_claim
result=PASS
rollback_command=$ROLLBACK_CMD
replay_command=$REPLAY_CMD
challenge_reexec_entry=$CHALLENGE_REEXEC_ENTRY
replay_env_trnm_challenge_reexec_entry=$REPLAY_ENV_ENTRY
EOF

cat >"$MANIFEST_PATH" <<EOF
manifest_path=$MANIFEST_PATH_CANONICAL
generated_at=2026-04-11T00:01:00Z
git_toplevel=$WORKTREE_ROOT
git_branch=$BRANCH_SHORT
git_head=$HEAD_SHA
git_head_state=attached
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_expected_worktree_branch_ref=$BRANCH_REF
git_worktree_branch_ref_match=true
git_status_summary=clean
truth_source=$WORKTREE_ROOT/RELEASE_READINESS.md
historical_evidence_only=false
evidence_scope=local_rc_rehearsal_not_current_release_ready_claim
rollback_command=$ROLLBACK_CMD
replay_command=$REPLAY_CMD
EOF

cat >"$PREFLIGHT_PATH" <<EOF
status=PASS
EOF

bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$TMP_OUT"

grep -q "^preflight_summary_path=$PREFLIGHT_PATH_CANONICAL$" "$TMP_OUT"
grep -q "^summary_path=$SUMMARY_PATH_CANONICAL$" "$TMP_OUT"
grep -q "^manifest_path=$MANIFEST_PATH_CANONICAL$" "$TMP_OUT"
grep -q "^git_worktree_branch_ref=$BRANCH_REF$" "$TMP_OUT"
grep -q "^git_expected_worktree_branch_ref=$BRANCH_REF$" "$TMP_OUT"
grep -q "^git_worktree_branch_ref_match=true$" "$TMP_OUT"
grep -q "^ticket_expected_branch_ref=$BRANCH_SHORT$" "$TMP_OUT"
grep -q "^expected_branch_ref=$BRANCH_REF$" "$TMP_OUT"
grep -q "^summary_rollback_command=$ROLLBACK_CMD$" "$TMP_OUT"
grep -q "^summary_replay_command=$REPLAY_CMD$" "$TMP_OUT"
grep -q "^manifest_rollback_command=$ROLLBACK_CMD$" "$TMP_OUT"
grep -q "^manifest_replay_command=$REPLAY_CMD$" "$TMP_OUT"

echo "PASS"
