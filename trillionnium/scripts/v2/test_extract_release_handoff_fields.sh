#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORKTREE_ROOT="$(cd "$ROOT/.." && pwd -P)"
SCRIPT="$ROOT/scripts/v2/extract_release_handoff_fields.sh"

BRANCH_SHORT="$(git -C "$WORKTREE_ROOT" branch --show-current)"
[ -n "$BRANCH_SHORT" ] || {
  echo "expected attached branch for test fixture" >&2
  exit 1
}

BRANCH_REF="$(git -C "$WORKTREE_ROOT" symbolic-ref -q HEAD)"
HEAD_SHA="$(git -C "$WORKTREE_ROOT" rev-parse HEAD)"
TRUTH_SOURCE="$WORKTREE_ROOT/RELEASE_READINESS.md"

STAMP="test-extract-release-handoff-fields-$$"
RUN_ROOT="$ROOT/run"
EVIDENCE_DIR="$RUN_ROOT/health/evidence-$STAMP"
RC_DIR="$ROOT/release/rc-$STAMP"
PREFLIGHT_DIR="$RUN_ROOT/preflight"
PREFLIGHT_BACKUP=""
PREFLIGHT_PATH="$PREFLIGHT_DIR/go-no-go-$STAMP.txt"
PREFLIGHT_ALIAS_PATH="$PREFLIGHT_DIR/go-no-go-latest.txt"

cleanup() {
  rm -rf "$EVIDENCE_DIR" "$RC_DIR"
  rm -f "$PREFLIGHT_PATH"
  if [ -n "$PREFLIGHT_BACKUP" ] && [ -d "$PREFLIGHT_BACKUP" ]; then
    rm -rf "$PREFLIGHT_DIR"
    mv "$PREFLIGHT_BACKUP" "$PREFLIGHT_DIR"
  fi
}
trap cleanup EXIT

mkdir -p "$RUN_ROOT/health" "$ROOT/release"
if [ -e "$PREFLIGHT_DIR" ]; then
  PREFLIGHT_BACKUP="$RUN_ROOT/preflight.$STAMP.bak"
  mv "$PREFLIGHT_DIR" "$PREFLIGHT_BACKUP"
fi
mkdir -p "$EVIDENCE_DIR" "$RC_DIR" "$PREFLIGHT_DIR"

SUMMARY_PATH="$EVIDENCE_DIR/summary.txt"
MANIFEST_PATH="$RC_DIR/manifest.txt"
SUMMARY_PATH_CANONICAL="$(cd "$(dirname "$SUMMARY_PATH")" && pwd -P)/$(basename "$SUMMARY_PATH")"
MANIFEST_PATH_CANONICAL="$(cd "$(dirname "$MANIFEST_PATH")" && pwd -P)/$(basename "$MANIFEST_PATH")"
PREFLIGHT_PATH_CANONICAL="$(cd "$(dirname "$PREFLIGHT_PATH")" && pwd -P)/$(basename "$PREFLIGHT_PATH")"
PREFLIGHT_ALIAS_PATH_CANONICAL="$(cd "$(dirname "$PREFLIGHT_ALIAS_PATH")" && pwd -P)/$(basename "$PREFLIGHT_ALIAS_PATH")"

cat >"$SUMMARY_PATH" <<EOF
result=PASS
generated_at=2026-04-12T03:17:00Z
git_toplevel=$WORKTREE_ROOT
git_branch=$BRANCH_SHORT
git_head=$HEAD_SHA
git_head_state=attached
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_expected_worktree_branch_ref=$BRANCH_REF
git_worktree_branch_ref_match=true
git_status_summary=clean
truth_source=$TRUTH_SOURCE
historical_evidence_only=true
evidence_scope=local_rc_rehearsal_not_current_release_ready_claim
rollback_command=git checkout -- trillionnium/docs/release/TRNM_MAINNET_REHEARSAL_GO_NOGO_TEMPLATE.md
replay_command=env TZ=UTC ./scripts/run_local_release_evidence.sh
challenge_reexec_entry=<entry_not_found>
replay_env_trnm_challenge_reexec_entry=<entry_not_found>
EOF

cat >"$MANIFEST_PATH" <<EOF
generated_at=2026-04-12T03:18:00Z
git_toplevel=$WORKTREE_ROOT
git_branch=$BRANCH_SHORT
git_head=$HEAD_SHA
git_head_state=attached
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_expected_worktree_branch_ref=$BRANCH_REF
git_worktree_branch_ref_match=true
git_status_summary=clean
truth_source=$TRUTH_SOURCE
historical_evidence_only=true
evidence_scope=local_rc_rehearsal_not_current_release_ready_claim
rollback_command=rm -rf '$RC_DIR'
replay_command=env TZ=UTC ./scripts/release_rc.sh
EOF

bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_REF" \
  >"$EVIDENCE_DIR/out-missing-preflight.txt"

grep -q "^preflight_path=<missing>$" "$EVIDENCE_DIR/out-missing-preflight.txt"
grep -q "^preflight_summary_path=<missing>$" "$EVIDENCE_DIR/out-missing-preflight.txt"
grep -q "^summary_path=$SUMMARY_PATH_CANONICAL$" "$EVIDENCE_DIR/out-missing-preflight.txt"
grep -q "^manifest_path=$MANIFEST_PATH_CANONICAL$" "$EVIDENCE_DIR/out-missing-preflight.txt"

cat >"$PREFLIGHT_PATH" <<EOF
result=GO
generated_at=2026-04-12T03:16:00Z
EOF
cp "$PREFLIGHT_PATH" "$PREFLIGHT_ALIAS_PATH"

bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" \
  >"$EVIDENCE_DIR/out-short-branch.txt"

grep -q "^verified_branch_ref=$BRANCH_REF$" "$EVIDENCE_DIR/out-short-branch.txt"
grep -q "^ticket_expected_branch_ref=$BRANCH_SHORT$" "$EVIDENCE_DIR/out-short-branch.txt"
grep -q "^expected_branch_ref=$BRANCH_REF$" "$EVIDENCE_DIR/out-short-branch.txt"
grep -q "^preflight_path=$PREFLIGHT_ALIAS_PATH_CANONICAL$" "$EVIDENCE_DIR/out-short-branch.txt"
grep -q "^preflight_summary_path=$PREFLIGHT_PATH_CANONICAL$" "$EVIDENCE_DIR/out-short-branch.txt"

echo "PASS"
