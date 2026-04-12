#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORKTREE_ROOT="$(git -C "$ROOT" rev-parse --show-toplevel)"
SCRIPT="$ROOT/scripts/v2/extract_release_handoff_fields.sh"

BRANCH_SHORT="$(git -C "$WORKTREE_ROOT" branch --show-current)"
[ -n "$BRANCH_SHORT" ] || {
  echo "expected attached branch for test fixture" >&2
  exit 1
}

BRANCH_REF="$(git -C "$WORKTREE_ROOT" symbolic-ref -q HEAD)"
HEAD_SHA="$(git -C "$WORKTREE_ROOT" rev-parse HEAD)"
TRUTH_SOURCE="$WORKTREE_ROOT/RELEASE_READINESS.md"
ROLLBACK_CMD="git reset --hard $HEAD_SHA"
REPLAY_CMD="./scripts/run_local_release_evidence.sh --expected-worktree-root $WORKTREE_ROOT --expected-branch-ref $BRANCH_SHORT"
CHALLENGE_REEXEC_ENTRY="trillionnium/challenges/example.json"
REPLAY_ENV_ENTRY="TRNM_CHALLENGE_REEXEC_ENTRY=$CHALLENGE_REEXEC_ENTRY"

STAMP="test-extract-release-handoff-fields-$$"
RUN_ROOT="$ROOT/run"
EVIDENCE_DIR="$RUN_ROOT/health/evidence-$STAMP"
RC_DIR="$ROOT/release/rc-$STAMP"
PREFLIGHT_DIR="$RUN_ROOT/preflight"
PREFLIGHT_BACKUP=""
PREFLIGHT_PATH="$PREFLIGHT_DIR/go-no-go-latest.txt"

cleanup() {
  rm -rf "$EVIDENCE_DIR" "$RC_DIR"
  if [ -n "$PREFLIGHT_BACKUP" ] && [ -d "$PREFLIGHT_BACKUP" ]; then
    rm -rf "$PREFLIGHT_DIR"
    mv "$PREFLIGHT_BACKUP" "$PREFLIGHT_DIR"
  else
    rm -rf "$PREFLIGHT_DIR"
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

write_summary() {
  cat >"$SUMMARY_PATH" <<EOF
summary_path=$SUMMARY_PATH_CANONICAL
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
historical_evidence_only=false
evidence_scope=local_rc_rehearsal_not_current_release_ready_claim
result=PASS
rollback_command=$ROLLBACK_CMD
replay_command=$REPLAY_CMD
challenge_reexec_entry=$CHALLENGE_REEXEC_ENTRY
replay_env_trnm_challenge_reexec_entry=$REPLAY_ENV_ENTRY
EOF
}

write_manifest() {
  cat >"$MANIFEST_PATH" <<EOF
manifest_path=$MANIFEST_PATH_CANONICAL
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
historical_evidence_only=false
evidence_scope=local_rc_rehearsal_not_current_release_ready_claim
rollback_command=$ROLLBACK_CMD
replay_command=$REPLAY_CMD
EOF
}

write_latest_preflight() {
  local result="$1"
  local branch_ref="$2"
  local match_flag="$3"
  cat >"$PREFLIGHT_PATH" <<EOF
result=$result
generated_at=2026-04-12T03:16:00Z
git_toplevel=$WORKTREE_ROOT
git_branch=$BRANCH_SHORT
git_head=$HEAD_SHA
git_head_state=attached
git_status_summary=clean
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$branch_ref
git_expected_worktree_branch_ref=$BRANCH_REF
git_worktree_branch_ref_match=$match_flag
expected_worktree_root=$WORKTREE_ROOT
expected_branch_ref=$BRANCH_REF
expected_head=$HEAD_SHA
rollback_command=git checkout -- run/preflight/go-no-go-latest.txt
replay_command=./scripts/testnet_preflight.sh
EOF
}

write_summary
write_manifest
write_latest_preflight PASS "$BRANCH_REF" true

bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" \
  --expected-head "$HEAD_SHA" >"$RUN_ROOT/out-short-$STAMP.txt"

OUT_SHORT="$RUN_ROOT/out-short-$STAMP.txt"
grep -q "^preflight_path=$PREFLIGHT_PATH_CANONICAL$" "$OUT_SHORT"
grep -q "^preflight_summary_path=$PREFLIGHT_PATH_CANONICAL$" "$OUT_SHORT"
grep -q "^preflight_result=PASS$" "$OUT_SHORT"
grep -q "^preflight_git_worktree_path=$WORKTREE_ROOT$" "$OUT_SHORT"
grep -q "^preflight_git_worktree_branch_ref=$BRANCH_REF$" "$OUT_SHORT"
grep -q "^preflight_git_worktree_branch_ref_match=true$" "$OUT_SHORT"
grep -q "^preflight_expected_worktree_root=$WORKTREE_ROOT$" "$OUT_SHORT"
grep -q "^preflight_ticket_expected_branch_ref=$BRANCH_SHORT$" "$OUT_SHORT"
grep -q "^preflight_expected_branch_ref=$BRANCH_REF$" "$OUT_SHORT"
grep -q "^preflight_expected_head=$HEAD_SHA$" "$OUT_SHORT"
grep -q '^preflight_rollback_command=git checkout -- run/preflight/go-no-go-latest.txt$' "$OUT_SHORT"
grep -q '^preflight_replay_command=./scripts/testnet_preflight.sh$' "$OUT_SHORT"
grep -q "^summary_path=$SUMMARY_PATH_CANONICAL$" "$OUT_SHORT"
grep -q "^manifest_path=$MANIFEST_PATH_CANONICAL$" "$OUT_SHORT"
grep -q "^ticket_expected_branch_ref=$BRANCH_SHORT$" "$OUT_SHORT"
grep -q "^expected_branch_ref=$BRANCH_REF$" "$OUT_SHORT"
grep -q "^expected_head=$HEAD_SHA$" "$OUT_SHORT"
grep -q "^git_worktree_branch_ref=$BRANCH_REF$" "$OUT_SHORT"
grep -q "^git_expected_worktree_branch_ref=$BRANCH_REF$" "$OUT_SHORT"
grep -q '^git_worktree_branch_ref_match=true$' "$OUT_SHORT"
grep -q "^summary_rollback_command=$ROLLBACK_CMD$" "$OUT_SHORT"
grep -q "^summary_replay_command=$REPLAY_CMD$" "$OUT_SHORT"
grep -q "^manifest_rollback_command=$ROLLBACK_CMD$" "$OUT_SHORT"
grep -q "^manifest_replay_command=$REPLAY_CMD$" "$OUT_SHORT"
grep -q "^challenge_reexec_entry=$CHALLENGE_REEXEC_ENTRY$" "$OUT_SHORT"
grep -q "^replay_env_trnm_challenge_reexec_entry=$REPLAY_ENV_ENTRY$" "$OUT_SHORT"

BAD_HEAD="0000000000000000000000000000000000000000"
if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" \
  --expected-head "$BAD_HEAD" >"$RUN_ROOT/out-bad-head-$STAMP.txt" 2>"$RUN_ROOT/err-bad-head-$STAMP.txt"; then
  echo "expected head mismatch to fail closed" >&2
  exit 1
fi
grep -q "^head mismatch: expected $BAD_HEAD got $HEAD_SHA$" "$RUN_ROOT/err-bad-head-$STAMP.txt"

cat >"$SUMMARY_PATH" <<EOF
generated_at=2026-04-12T03:17:00Z
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
truth_source=$TRUTH_SOURCE
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
  --expected-branch-ref "$BRANCH_SHORT" >"$RUN_ROOT/out-summary-duplicate-key-$STAMP.txt" 2>"$RUN_ROOT/err-summary-duplicate-key-$STAMP.txt"; then
  echo "expected duplicate summary git_worktree_branch_ref to fail closed" >&2
  exit 1
fi
grep -q "^duplicate git_worktree_branch_ref in $SUMMARY_PATH$" "$RUN_ROOT/err-summary-duplicate-key-$STAMP.txt"
write_summary

cat >"$PREFLIGHT_PATH" <<EOF
result=PASS
generated_at=2026-04-12T03:16:00Z
git_toplevel=$WORKTREE_ROOT
git_branch=$BRANCH_SHORT
git_head=$HEAD_SHA
git_head_state=attached
git_status_summary=clean
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_expected_worktree_branch_ref=$BRANCH_REF
git_worktree_branch_ref_match=true
git_worktree_branch_ref_match=false
expected_worktree_root=$WORKTREE_ROOT
expected_branch_ref=$BRANCH_REF
expected_head=$HEAD_SHA
rollback_command=git checkout -- run/preflight/go-no-go-latest.txt
replay_command=./scripts/testnet_preflight.sh
EOF
if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$RUN_ROOT/out-preflight-duplicate-key-$STAMP.txt" 2>"$RUN_ROOT/err-preflight-duplicate-key-$STAMP.txt"; then
  echo "expected duplicate preflight git_worktree_branch_ref_match to fail closed" >&2
  exit 1
fi
grep -q "^duplicate git_worktree_branch_ref_match in $PREFLIGHT_PATH$" "$RUN_ROOT/err-preflight-duplicate-key-$STAMP.txt"
write_latest_preflight PASS "$BRANCH_REF" true

cat >"$PREFLIGHT_PATH" <<EOF
result=PASS
generated_at=2026-04-12T03:16:15Z
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
  --expected-branch-ref "$BRANCH_SHORT" >"$RUN_ROOT/out-preflight-missing-field-$STAMP.txt" 2>"$RUN_ROOT/err-preflight-missing-field-$STAMP.txt"; then
  echo "expected missing preflight git_worktree_branch_ref_match to fail closed" >&2
  exit 1
fi
grep -q "^missing git_worktree_branch_ref_match in $PREFLIGHT_PATH$" "$RUN_ROOT/err-preflight-missing-field-$STAMP.txt"
write_latest_preflight PASS "$BRANCH_REF" true

write_latest_preflight FAIL "$BRANCH_REF" true
if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$RUN_ROOT/out-preflight-fail-$STAMP.txt" 2>"$RUN_ROOT/err-preflight-fail-$STAMP.txt"; then
  echo "expected failing preflight result to fail closed" >&2
  exit 1
fi
grep -q '^artifact mismatch for preflight result: expected PASS got FAIL$' "$RUN_ROOT/err-preflight-fail-$STAMP.txt"
write_latest_preflight PASS "$BRANCH_REF" true

write_latest_preflight PASS refs/heads/lane/not-this-lane true
if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$RUN_ROOT/out-mismatch-$STAMP.txt" 2>"$RUN_ROOT/err-mismatch-$STAMP.txt"; then
  echo "expected preflight branch mismatch to fail" >&2
  exit 1
fi
grep -q '^artifact mismatch for preflight git_worktree_branch_ref:' "$RUN_ROOT/err-mismatch-$STAMP.txt"
write_latest_preflight PASS "$BRANCH_REF" true

rm -f "$PREFLIGHT_PATH"
ln -s "$SUMMARY_PATH" "$PREFLIGHT_PATH"
if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$RUN_ROOT/out-preflight-same-summary-$STAMP.txt" 2>"$RUN_ROOT/err-preflight-same-summary-$STAMP.txt"; then
  echo "expected preflight artifact aliasing summary to fail" >&2
  exit 1
fi
grep -q "^preflight summary path must be distinct from summary/manifest artifacts: $SUMMARY_PATH_CANONICAL$" "$RUN_ROOT/err-preflight-same-summary-$STAMP.txt"

rm -f "$PREFLIGHT_PATH"
ln -s "$MANIFEST_PATH" "$PREFLIGHT_PATH"
if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$RUN_ROOT/out-preflight-same-manifest-$STAMP.txt" 2>"$RUN_ROOT/err-preflight-same-manifest-$STAMP.txt"; then
  echo "expected preflight artifact aliasing manifest to fail" >&2
  exit 1
fi
grep -q "^preflight summary path must be distinct from summary/manifest artifacts: $MANIFEST_PATH_CANONICAL$" "$RUN_ROOT/err-preflight-same-manifest-$STAMP.txt"

rm -f "$PREFLIGHT_PATH"
write_latest_preflight PASS "$BRANCH_REF" true
STAMPED_PREFLIGHT_PATH="$PREFLIGHT_DIR/go-no-go-20260412T031500Z.txt"
STAMPED_PREFLIGHT_PATH_CANONICAL="$(cd "$(dirname "$STAMPED_PREFLIGHT_PATH")" && pwd -P)/$(basename "$STAMPED_PREFLIGHT_PATH")"
cat >"$STAMPED_PREFLIGHT_PATH" <<EOF
result=PASS
generated_at=2026-04-12T03:15:00Z
git_toplevel=$WORKTREE_ROOT
git_branch=$BRANCH_SHORT
git_head=$HEAD_SHA
git_head_state=attached
git_status_summary=clean
git_worktree_path=$WORKTREE_ROOT
git_worktree_branch_ref=$BRANCH_REF
git_expected_worktree_branch_ref=$BRANCH_REF
git_worktree_branch_ref_match=true
expected_worktree_root=$WORKTREE_ROOT
expected_branch_ref=$BRANCH_REF
expected_head=$HEAD_SHA
rollback_command=git checkout -- $STAMPED_PREFLIGHT_PATH
replay_command=./scripts/testnet_preflight.sh --from stamped
EOF
bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$RUN_ROOT/out-preflight-stamped-$STAMP.txt"
OUT_STAMPED="$RUN_ROOT/out-preflight-stamped-$STAMP.txt"
grep -q "^preflight_path=$PREFLIGHT_PATH_CANONICAL$" "$OUT_STAMPED"
grep -q "^preflight_summary_path=$STAMPED_PREFLIGHT_PATH_CANONICAL$" "$OUT_STAMPED"
grep -q '^preflight_generated_at=2026-04-12T03:15:00Z$' "$OUT_STAMPED"
grep -q "^preflight_rollback_command=git checkout -- $STAMPED_PREFLIGHT_PATH$" "$OUT_STAMPED"
grep -q '^preflight_replay_command=./scripts/testnet_preflight.sh --from stamped$' "$OUT_STAMPED"
rm -f "$STAMPED_PREFLIGHT_PATH"
write_latest_preflight PASS "$BRANCH_REF" true

if bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$SUMMARY_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_SHORT" >"$RUN_ROOT/out-same-artifact-$STAMP.txt" 2>"$RUN_ROOT/err-same-artifact-$STAMP.txt"; then
  echo "expected identical summary/manifest path to fail" >&2
  exit 1
fi
grep -q "^summary and manifest paths must be distinct artifacts: $SUMMARY_PATH_CANONICAL$" "$RUN_ROOT/err-same-artifact-$STAMP.txt"

bash "$SCRIPT" \
  --summary-path "$SUMMARY_PATH" \
  --manifest-path "$MANIFEST_PATH" \
  --expected-worktree-root "$WORKTREE_ROOT" \
  --expected-branch-ref "$BRANCH_REF" \
  --expected-head "$HEAD_SHA" >"$RUN_ROOT/out-full-$STAMP.txt"
OUT_FULL="$RUN_ROOT/out-full-$STAMP.txt"
grep -q "^ticket_expected_branch_ref=$BRANCH_REF$" "$OUT_FULL"
grep -q "^expected_branch_ref=$BRANCH_REF$" "$OUT_FULL"
grep -q "^expected_head=$HEAD_SHA$" "$OUT_FULL"
grep -q "^git_worktree_branch_ref=$BRANCH_REF$" "$OUT_FULL"
grep -q "^git_expected_worktree_branch_ref=$BRANCH_REF$" "$OUT_FULL"
grep -q "^challenge_reexec_entry=$CHALLENGE_REEXEC_ENTRY$" "$OUT_FULL"
grep -q "^replay_env_trnm_challenge_reexec_entry=$REPLAY_ENV_ENTRY$" "$OUT_FULL"

rm -f "$OUT_SHORT" "$OUT_STAMPED" "$OUT_FULL" \
  "$RUN_ROOT/out-bad-head-$STAMP.txt" "$RUN_ROOT/err-bad-head-$STAMP.txt" \
  "$RUN_ROOT/out-summary-duplicate-key-$STAMP.txt" "$RUN_ROOT/err-summary-duplicate-key-$STAMP.txt" \
  "$RUN_ROOT/out-preflight-duplicate-key-$STAMP.txt" "$RUN_ROOT/err-preflight-duplicate-key-$STAMP.txt" \
  "$RUN_ROOT/out-preflight-missing-field-$STAMP.txt" "$RUN_ROOT/err-preflight-missing-field-$STAMP.txt" \
  "$RUN_ROOT/out-preflight-fail-$STAMP.txt" "$RUN_ROOT/err-preflight-fail-$STAMP.txt" \
  "$RUN_ROOT/out-mismatch-$STAMP.txt" "$RUN_ROOT/err-mismatch-$STAMP.txt" \
  "$RUN_ROOT/out-preflight-same-summary-$STAMP.txt" "$RUN_ROOT/err-preflight-same-summary-$STAMP.txt" \
  "$RUN_ROOT/out-preflight-same-manifest-$STAMP.txt" "$RUN_ROOT/err-preflight-same-manifest-$STAMP.txt" \
  "$RUN_ROOT/out-same-artifact-$STAMP.txt" "$RUN_ROOT/err-same-artifact-$STAMP.txt"

echo "PASS"
