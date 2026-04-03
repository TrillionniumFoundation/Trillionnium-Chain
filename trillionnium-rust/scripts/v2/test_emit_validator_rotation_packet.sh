#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/v2/emit_validator_rotation_packet.sh"

common_args=(
  --cutover-kind dr_rebuild
  --verified-worktree /tmp/trnm-lane
  --verified-branch-ref lane/mn05-operator-dr-rotation-lifecycle
  --verified-head 0123456789abcdef
  --outgoing-validator-id validator-old
  --incoming-validator-id validator-new
  --incoming-config-path /tmp/configs/validator-new.json
  --rollback-command 'rm -rf /tmp/cutover-note'
  --handoff-signed-by alice
  --handoff-acknowledged-by bob
  --dr-summary-path /tmp/run/bft-restart-recovery-1.txt
  --dr-generated-at 2026-04-03T06:14:00Z
  --dr-status PASS
  --dr-replay-command './scripts/check_bft_restart_recovery.sh --config /tmp/configs/validator-new.json'
  --dr-rollback-command 'rm -rf /tmp/run/bft-restart-recovery-1.txt'
)

if bash "$SCRIPT" "${common_args[@]}" >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected dr_rebuild without lane binding to fail" >&2
  exit 1
fi
grep -q 'missing --expected-worktree-root' /tmp/emit-packet.err

bash "$SCRIPT" \
  "${common_args[@]}" \
  --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle \
  --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --lane-verify-command './scripts/v2/verify_lane_worktree.sh --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle' \
  >/tmp/emit-packet.out

grep -q '^expected_worktree_root=/Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle$' /tmp/emit-packet.out
grep -q '^dr_status=PASS$' /tmp/emit-packet.out

echo "PASS"
