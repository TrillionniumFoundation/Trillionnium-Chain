#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="$ROOT/trillionnium/docs/runbooks/genesis-generation-checklist.md"

if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] missing genesis generation checklist: $TARGET" >&2
  exit 1
fi

required_lines=(
  'Required for `public-mainnet-input` evidence:'
  '`operator_ack_signature_path=` or `operator_ack_digest=` when durable acknowledgment is required'
  '`dr_summary_path=` pointing to the same bootstrap window'
  '`dr_generated_at=` in UTC for the DR summary above'
  '`dr_status=ready|not_needed|blocked`'
  '`dr_replay_command=` with an explicit worktree/workspace-scoped command'
  '`dr_rollback_command=` with the exact fail-closed rollback entrypoint'
  '`previous_stable_anchor=` naming the last known-good genesis artifact/hash or ceremony packet anchor that rollback returns to'
  'operator acknowledgment signature path or digest used for durable sign-off'
  'DR summary path'
  'DR generated-at timestamp'
  'DR status'
  'DR replay command'
  'DR rollback command'
  'previous stable anchor'
  '`dr_status=ready` but `dr_summary_path=`, `dr_generated_at=`, `dr_replay_command=`, or `dr_rollback_command=` is missing'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$TARGET"; then
    echo "[FAIL] missing genesis DR evidence guard line: $line" >&2
    exit 1
  fi
done

echo "[PASS] genesis generation checklist requires operator ack binding plus DR summary/status/replay/rollback evidence for public-mainnet handoff"
