#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/v2/extract_release_handoff_fields.sh"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR" "$SUMMARY_DIR" "$MANIFEST_DIR"; rm -f "$PREFLIGHT_PATH"' EXIT

cd "$ROOT"

WORKTREE_ROOT="$(git rev-parse --show-toplevel)"
BRANCH_SHORT="$(git branch --show-current)"
BRANCH_REF="refs/heads/$BRANCH_SHORT"
HEAD_SHA="$(git rev-parse HEAD)"
SUMMARY_DIR="$ROOT/run/health/evidence-test-extract-release-handoff-fields-$$"
MANIFEST_DIR="$ROOT/release/rc-test-extract-release-handoff-fields-$$"
PREFLIGHT_DIR="$ROOT/run/preflight"
PREFLIGHT_PATH="$PREFLIGHT_DIR/go-no-go-latest.txt"
SUMMARY_PATH="$SUMMARY_DIR/summary.txt"
MANIFEST_PATH="$MANIFEST_DIR/manifest.txt"

mkdir -p "$SUMMARY_DIR" "$MANIFEST_DIR" "$PREFLIGHT_DIR"

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
grep -q "^preflight_summary_path=$PREFLIGHT_PATH$" "$TMPDIR/out-short.txt"
grep -q '^preflight_result=PASS$' "$TMPDIR/out-short.txt"
grep -q '^preflight_generated_at=2026-04-11T01:01:00Z$' "$TMPDIR/out-short.txt"
grep -q '^preflight_git_status_summary=clean$' "$TMPDIR/out-short.txt"
grep -q "^preflight_git_worktree_path=$WORKTREE_ROOT$" "$TMPDIR/out-short.txt"
grep -q "^preflight_git_worktree_branch_ref=$BRANCH_REF$" "$TMPDIR/out-short.txt"
grep -q '^preflight_git_worktree_branch_ref_match=true$' "$TMPDIR/out-short.txt"
grep -q '^preflight_rollback_command=git checkout -- run/preflight/go-no-go-latest.txt$' "$TMPDIR/out-short.txt"
grep -q '^preflight_replay_command=./scripts/testnet_preflight.sh$' "$TMPDIR/out-short.txt"

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
grep -q "^preflight summary path must be distinct from summary/manifest artifacts: $SUMMARY_PATH$" "$TMPDIR/err-preflight-same-summary.txt"

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
grep -q "^summary and manifest paths must be distinct artifacts: $SUMMARY_PATH$" "$TMPDIR/err-same-artifact.txt"

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
