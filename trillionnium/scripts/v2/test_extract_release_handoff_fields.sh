#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/v2/extract_release_handoff_fields.sh"
SUFFIX="test-extract-release-handoff-fields-$$"
SUMMARY_DIR="$ROOT/run/health/evidence-$SUFFIX"
MANIFEST_DIR="$ROOT/release/rc-$SUFFIX"
PREFLIGHT_DIR="$ROOT/run/preflight"
PREFLIGHT_PATH="$PREFLIGHT_DIR/go-no-go-latest.txt"
TMPDIR="$(mktemp -d)"
BACKUP_PREFLIGHT=""

cleanup() {
  rm -rf "$TMPDIR" "$SUMMARY_DIR" "$MANIFEST_DIR"
  if [ -n "$BACKUP_PREFLIGHT" ] && [ -f "$BACKUP_PREFLIGHT" ]; then
    mv "$BACKUP_PREFLIGHT" "$PREFLIGHT_PATH"
  else
    rm -f "$PREFLIGHT_PATH"
  fi
}
trap cleanup EXIT

mkdir -p "$SUMMARY_DIR" "$MANIFEST_DIR" "$PREFLIGHT_DIR"
if [ -e "$PREFLIGHT_PATH" ] || [ -L "$PREFLIGHT_PATH" ]; then
  BACKUP_PREFLIGHT="$PREFLIGHT_PATH.$$.bak"
  cp -P "$PREFLIGHT_PATH" "$BACKUP_PREFLIGHT"
fi

cd "$ROOT"
WORKTREE_ROOT="$(git rev-parse --show-toplevel)"
BRANCH_SHORT="$(git branch --show-current)"
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

cat >"$PREFLIGHT_PATH" <<EOF
result=PASS
generated_at=2026-04-11T01:01:00Z
git_status_summary=clean
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_worktree_branch_ref_match=true
rollback_command=git checkout -- run/preflight/go-no-go-latest.txt
replay_command=./scripts/testnet_preflight.sh
EOF

cat >"$SUMMARY_PATH" <<EOF
summary_path=$SUMMARY_PATH_CANONICAL
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
truth_source=$WORKTREE_ROOT/RELEASE_READINESS.md
historical_evidence_only=false
evidence_scope=local_rc_rehearsal_not_current_release_ready_claim
rollback_command=$ROLLBACK_CMD
replay_command=$REPLAY_CMD
EOF

bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" \
  --expected-head "$HEAD_SHA" >"$TMPDIR/out-short.txt"

grep -q "^ticket_expected_branch_ref=$BRANCH_SHORT$" "$TMPDIR/out-short.txt"
grep -q "^expected_branch_ref=$BRANCH_REF$" "$TMPDIR/out-short.txt"
grep -q "^expected_head=$HEAD_SHA$" "$TMPDIR/out-short.txt"
grep -q "^preflight_summary_path=$PREFLIGHT_PATH_CANONICAL$" "$TMPDIR/out-short.txt"
grep -q "^summary_path=$SUMMARY_PATH_CANONICAL$" "$TMPDIR/out-short.txt"
grep -q "^manifest_path=$MANIFEST_PATH_CANONICAL$" "$TMPDIR/out-short.txt"
grep -q '^preflight_result=PASS$' "$TMPDIR/out-short.txt"
grep -q '^preflight_generated_at=2026-04-11T01:01:00Z$' "$TMPDIR/out-short.txt"
grep -q '^preflight_git_status_summary=clean$' "$TMPDIR/out-short.txt"
grep -q "^preflight_git_worktree_path=$WORKTREE_ROOT$" "$TMPDIR/out-short.txt"
grep -q "^preflight_git_worktree_branch_ref=$BRANCH_REF$" "$TMPDIR/out-short.txt"
grep -q '^preflight_git_worktree_branch_ref_match=true$' "$TMPDIR/out-short.txt"
grep -q '^preflight_rollback_command=git checkout -- run/preflight/go-no-go-latest.txt$' "$TMPDIR/out-short.txt"
grep -q '^preflight_replay_command=./scripts/testnet_preflight.sh$' "$TMPDIR/out-short.txt"
grep -q "^git_worktree_branch_ref=$BRANCH_REF$" "$TMPDIR/out-short.txt"
grep -q "^git_expected_worktree_branch_ref=$BRANCH_REF$" "$TMPDIR/out-short.txt"
grep -q '^git_worktree_branch_ref_match=true$' "$TMPDIR/out-short.txt"
grep -q "^summary_rollback_command=$ROLLBACK_CMD$" "$TMPDIR/out-short.txt"
grep -q "^summary_replay_command=$REPLAY_CMD$" "$TMPDIR/out-short.txt"
grep -q "^manifest_rollback_command=$ROLLBACK_CMD$" "$TMPDIR/out-short.txt"
grep -q "^manifest_replay_command=$REPLAY_CMD$" "$TMPDIR/out-short.txt"
grep -q "^challenge_reexec_entry=$CHALLENGE_REEXEC_ENTRY$" "$TMPDIR/out-short.txt"
grep -q "^replay_env_trnm_challenge_reexec_entry=$REPLAY_ENV_ENTRY$" "$TMPDIR/out-short.txt"

BAD_HEAD="0000000000000000000000000000000000000000"
if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" \
  --expected-head "$BAD_HEAD" >"$TMPDIR/out-bad-head.txt" 2>"$TMPDIR/err-bad-head.txt"; then
  echo "expected head mismatch to fail closed" >&2
  exit 1
fi
grep -q "^head mismatch: expected $BAD_HEAD got $HEAD_SHA$" "$TMPDIR/err-bad-head.txt"

cat >"$SUMMARY_PATH" <<EOF
generated_at=2026-04-11T01:05:00Z
git_toplevel=$WORKTREE_ROOT
git_branch=$BRANCH_SHORT
git_head=$HEAD_SHA
git_head_state=attached
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_worktree_branch_ref=refs/heads/lane/not-this-lane
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
if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$TMPDIR/out-summary-duplicate-key.txt" 2>"$TMPDIR/err-summary-duplicate-key.txt"; then
  echo "expected duplicate summary git_worktree_branch_ref to fail closed" >&2
  exit 1
fi
grep -q "^duplicate git_worktree_branch_ref in $SUMMARY_PATH$" "$TMPDIR/err-summary-duplicate-key.txt"

cat >"$SUMMARY_PATH" <<EOF
summary_path=$SUMMARY_PATH_CANONICAL
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
truth_source=$WORKTREE_ROOT/RELEASE_READINESS.md
historical_evidence_only=false
evidence_scope=local_rc_rehearsal_not_current_release_ready_claim
result=PASS
rollback_command=$ROLLBACK_CMD
replay_command=$REPLAY_CMD
challenge_reexec_entry=$CHALLENGE_REEXEC_ENTRY
replay_env_trnm_challenge_reexec_entry=$REPLAY_ENV_ENTRY
EOF

cat >"$PREFLIGHT_PATH" <<EOF
result=PASS
generated_at=2026-04-11T01:01:00Z
git_status_summary=clean
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_worktree_branch_ref_match=true
git_worktree_branch_ref_match=false
rollback_command=git checkout -- run/preflight/go-no-go-latest.txt
replay_command=./scripts/testnet_preflight.sh
EOF
if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$TMPDIR/out-preflight-duplicate-key.txt" 2>"$TMPDIR/err-preflight-duplicate-key.txt"; then
  echo "expected duplicate preflight git_worktree_branch_ref_match to fail closed" >&2
  exit 1
fi
grep -q "^duplicate git_worktree_branch_ref_match in $PREFLIGHT_PATH$" "$TMPDIR/err-preflight-duplicate-key.txt"

cat >"$PREFLIGHT_PATH" <<EOF
result=PASS
generated_at=2026-04-11T01:01:15Z
git_status_summary=clean
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
rollback_command=git checkout -- run/preflight/go-no-go-latest.txt
replay_command=./scripts/testnet_preflight.sh
EOF
if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$TMPDIR/out-preflight-missing-field.txt" 2>"$TMPDIR/err-preflight-missing-field.txt"; then
  echo "expected missing preflight git_worktree_branch_ref_match to fail closed" >&2
  exit 1
fi
grep -q "^missing git_worktree_branch_ref_match in $PREFLIGHT_PATH$" "$TMPDIR/err-preflight-missing-field.txt"

cat >"$PREFLIGHT_PATH" <<EOF
result=FAIL
generated_at=2026-04-11T01:01:30Z
git_status_summary=clean
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_worktree_branch_ref_match=true
rollback_command=git checkout -- run/preflight/go-no-go-latest.txt
replay_command=./scripts/testnet_preflight.sh
EOF
if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$TMPDIR/out-preflight-fail.txt" 2>"$TMPDIR/err-preflight-fail.txt"; then
  echo "expected failing preflight result to fail closed" >&2
  exit 1
fi
grep -q '^artifact mismatch for preflight result: expected PASS got FAIL$' "$TMPDIR/err-preflight-fail.txt"

cat >"$PREFLIGHT_PATH" <<EOF
result=PASS
generated_at=2026-04-11T01:02:00Z
git_status_summary=clean
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=refs/heads/lane/not-this-lane
git_worktree_branch_ref_match=true
rollback_command=git checkout -- run/preflight/go-no-go-latest.txt
replay_command=./scripts/testnet_preflight.sh
EOF
if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$TMPDIR/out-mismatch.txt" 2>"$TMPDIR/err-mismatch.txt"; then
  echo "expected preflight branch mismatch to fail" >&2
  exit 1
fi
grep -q '^artifact mismatch for preflight git_worktree_branch_ref:' "$TMPDIR/err-mismatch.txt"

rm -f "$PREFLIGHT_PATH"
ln -s "$SUMMARY_PATH" "$PREFLIGHT_PATH"
if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$TMPDIR/out-preflight-same-summary.txt" 2>"$TMPDIR/err-preflight-same-summary.txt"; then
  echo "expected preflight artifact aliasing summary to fail" >&2
  exit 1
fi
grep -q "^preflight summary path must be distinct from summary/manifest artifacts: $SUMMARY_PATH_CANONICAL$" "$TMPDIR/err-preflight-same-summary.txt"

rm -f "$PREFLIGHT_PATH"
ln -s "$MANIFEST_PATH" "$PREFLIGHT_PATH"
if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$TMPDIR/out-preflight-same-manifest.txt" 2>"$TMPDIR/err-preflight-same-manifest.txt"; then
  echo "expected preflight artifact aliasing manifest to fail" >&2
  exit 1
fi
grep -q "^preflight summary path must be distinct from summary/manifest artifacts: $MANIFEST_PATH_CANONICAL$" "$TMPDIR/err-preflight-same-manifest.txt"

rm -f "$PREFLIGHT_PATH"
STAMPED_PREFLIGHT_PATH="$PREFLIGHT_DIR/go-no-go-20260411T010500Z.txt"
cat >"$STAMPED_PREFLIGHT_PATH" <<EOF
result=PASS
generated_at=2026-04-11T01:05:00Z
git_status_summary=clean
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_worktree_branch_ref_match=true
rollback_command=git checkout -- $STAMPED_PREFLIGHT_PATH
replay_command=./scripts/testnet_preflight.sh --from stamped
EOF
bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$TMPDIR/out-preflight-stamped.txt"
grep -q "^preflight_summary_path=$STAMPED_PREFLIGHT_PATH$" "$TMPDIR/out-preflight-stamped.txt"
grep -q '^preflight_generated_at=2026-04-11T01:05:00Z$' "$TMPDIR/out-preflight-stamped.txt"
grep -q "^preflight_rollback_command=git checkout -- $STAMPED_PREFLIGHT_PATH$" "$TMPDIR/out-preflight-stamped.txt"
grep -q '^preflight_replay_command=./scripts/testnet_preflight.sh --from stamped$' "$TMPDIR/out-preflight-stamped.txt"
rm -f "$STAMPED_PREFLIGHT_PATH"

cat >"$PREFLIGHT_PATH" <<EOF
result=PASS
generated_at=2026-04-11T01:01:00Z
git_status_summary=clean
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_worktree_branch_ref_match=true
rollback_command=git checkout -- run/preflight/go-no-go-latest.txt
replay_command=./scripts/testnet_preflight.sh
EOF

if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$SUMMARY_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$TMPDIR/out-same-artifact.txt" 2>"$TMPDIR/err-same-artifact.txt"; then
  echo "expected identical summary/manifest path to fail" >&2
  exit 1
fi
grep -q "^summary and manifest paths must be distinct artifacts: $SUMMARY_PATH_CANONICAL$" "$TMPDIR/err-same-artifact.txt"

bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_REF" \
  --expected-head "$HEAD_SHA" >"$TMPDIR/out-full.txt"

grep -q "^ticket_expected_branch_ref=$BRANCH_REF$" "$TMPDIR/out-full.txt"
grep -q "^expected_branch_ref=$BRANCH_REF$" "$TMPDIR/out-full.txt"
grep -q "^expected_head=$HEAD_SHA$" "$TMPDIR/out-full.txt"
grep -q "^git_worktree_branch_ref=$BRANCH_REF$" "$TMPDIR/out-full.txt"
grep -q "^git_expected_worktree_branch_ref=$BRANCH_REF$" "$TMPDIR/out-full.txt"
grep -q "^challenge_reexec_entry=$CHALLENGE_REEXEC_ENTRY$" "$TMPDIR/out-full.txt"
grep -q "^replay_env_trnm_challenge_reexec_entry=$REPLAY_ENV_ENTRY$" "$TMPDIR/out-full.txt"

echo "PASS"
