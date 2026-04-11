#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/v2/extract_release_handoff_fields.sh"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR" "$SUMMARY_DIR" "$MANIFEST_DIR"' EXIT

cd "$ROOT"

WORKTREE_ROOT="$(git rev-parse --show-toplevel)"
BRANCH_SHORT="$(git branch --show-current)"
BRANCH_REF="refs/heads/$BRANCH_SHORT"
HEAD_SHA="$(git rev-parse HEAD)"
SUMMARY_DIR="$ROOT/run/health/evidence-test-extract-release-handoff-fields-$$"
MANIFEST_DIR="$ROOT/release/rc-test-extract-release-handoff-fields-$$"
SUMMARY_PATH="$SUMMARY_DIR/summary.txt"
MANIFEST_PATH="$MANIFEST_DIR/manifest.txt"

mkdir -p "$SUMMARY_DIR" "$MANIFEST_DIR"

cat >"$SUMMARY_PATH" <<EOF
generated_at=2026-04-11T01:05:00Z
git_toplevel=$WORKTREE_ROOT
git_branch=$BRANCH_SHORT
git_head=$HEAD_SHA
git_head_state=attached
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_expected_worktree_branch_ref=$BRANCH_REF
git_worktree_branch_ref_match=true
git_status_summary=clean
truth_source=RELEASE_READINESS.md
historical_evidence_only=true
evidence_scope=local_rc_rehearsal
result=PASS
rollback_command=git checkout -- trillionnium/scripts/v2/extract_release_handoff_fields.sh
replay_command=./scripts/run_local_release_evidence.sh
challenge_reexec_entry=<entry_not_found>
replay_env_trnm_challenge_reexec_entry=<entry_not_found>
EOF

cat >"$MANIFEST_PATH" <<EOF
generated_at=2026-04-11T01:07:00Z
git_toplevel=$WORKTREE_ROOT
git_branch=$BRANCH_SHORT
git_head=$HEAD_SHA
git_head_state=attached
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_expected_worktree_branch_ref=$BRANCH_REF
git_worktree_branch_ref_match=true
git_status_summary=clean
truth_source=RELEASE_READINESS.md
historical_evidence_only=true
evidence_scope=local_rc_rehearsal
rollback_command=git checkout -- trillionnium/scripts/v2/extract_release_handoff_fields.sh
replay_command=./scripts/release_rc.sh
EOF

bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$TMPDIR/out-short.txt"

grep -q "^ticket_expected_branch_ref=$BRANCH_SHORT$" "$TMPDIR/out-short.txt"
grep -q "^expected_branch_ref=$BRANCH_REF$" "$TMPDIR/out-short.txt"
grep -q "^git_worktree_branch_ref=$BRANCH_REF$" "$TMPDIR/out-short.txt"
grep -q "^git_expected_worktree_branch_ref=$BRANCH_REF$" "$TMPDIR/out-short.txt"

bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_REF" >"$TMPDIR/out-full.txt"

grep -q "^ticket_expected_branch_ref=$BRANCH_REF$" "$TMPDIR/out-full.txt"
grep -q "^expected_branch_ref=$BRANCH_REF$" "$TMPDIR/out-full.txt"
grep -q "^git_worktree_branch_ref=$BRANCH_REF$" "$TMPDIR/out-full.txt"
grep -q "^git_expected_worktree_branch_ref=$BRANCH_REF$" "$TMPDIR/out-full.txt"

[ "$(grep -c '^challenge_reexec_entry=<entry_not_found>$' "$TMPDIR/out-short.txt")" -eq 1 ]
[ "$(grep -c '^replay_env_trnm_challenge_reexec_entry=<entry_not_found>$' "$TMPDIR/out-short.txt")" -eq 1 ]
[ "$(grep -c '^challenge_reexec_entry=<entry_not_found>$' "$TMPDIR/out-full.txt")" -eq 1 ]
[ "$(grep -c '^replay_env_trnm_challenge_reexec_entry=<entry_not_found>$' "$TMPDIR/out-full.txt")" -eq 1 ]

echo "PASS"
