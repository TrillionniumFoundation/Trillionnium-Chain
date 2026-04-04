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

if bash "$SCRIPT" \
  --cutover-kind rotation \
  --verified-worktree /tmp/trnm-lane \
  --verified-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --verified-head 0123456789abcdef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected rotation without handoff sign-off to fail" >&2
  exit 1
fi
grep -q 'missing --handoff-signed-by' /tmp/emit-packet.err

if bash "$SCRIPT" \
  --cutover-kind replacement \
  --verified-worktree /tmp/trnm-lane \
  --verified-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --verified-head 0123456789abcdef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected partial lane binding fields to fail" >&2
  exit 1
fi
grep -q 'lane binding requires --expected-worktree-root, --expected-branch-ref, and --lane-verify-command together' /tmp/emit-packet.err

bash "$SCRIPT" \
  --cutover-kind replacement \
  --verified-worktree /tmp/trnm-lane \
  --verified-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --verified-head 0123456789abcdef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  >/tmp/emit-packet.out

grep -q '^cutover_kind=replacement$' /tmp/emit-packet.out
grep -q '^rollback_command=rm -rf /tmp/cutover-note$' /tmp/emit-packet.out

if bash "$SCRIPT" \
  --cutover-kind rotation \
  --verified-worktree /tmp/trnm-lane \
  --verified-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --verified-head 0123456789abcdef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  --handoff-signed-by alice \
  --handoff-acknowledged-by bob \
  --handoff-summary-path /tmp/run/health/evidence-20260403/summary.txt \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected partial handoff release artifact fields to fail" >&2
  exit 1
fi
grep -q 'missing --handoff-manifest-path' /tmp/emit-packet.err

if bash "$SCRIPT" \
  --cutover-kind rotation \
  --verified-worktree /tmp/trnm-lane \
  --verified-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --verified-head 0123456789abcdef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  --handoff-signed-by alice \
  --handoff-acknowledged-by bob \
  --dr-summary-path /tmp/run/bft-restart-recovery-1.txt \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected partial dr evidence fields to fail" >&2
  exit 1
fi
grep -q 'missing --dr-generated-at' /tmp/emit-packet.err

if bash "$SCRIPT" \
  --cutover-kind rotation \
  --verified-worktree /tmp/trnm-lane \
  --verified-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --verified-head 0123456789abcdef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  --handoff-signed-by alice \
  --handoff-acknowledged-by bob \
  --dr-summary-path /tmp/run/bft-restart-recovery-1.txt \
  --dr-generated-at 2026-04-03T06:14:00Z \
  --dr-status FAIL \
  --dr-replay-command './scripts/check_bft_restart_recovery.sh --config /tmp/configs/validator-new.json' \
  --dr-rollback-command 'rm -rf /tmp/run/bft-restart-recovery-1.txt' \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected non-PASS DR evidence to fail" >&2
  exit 1
fi
grep -q 'invalid --dr-status: expected PASS got FAIL' /tmp/emit-packet.err

if bash "$SCRIPT" \
  "${common_args[@]}" \
  --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle \
  --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --lane-verify-command './scripts/v2/verify_lane_worktree.sh --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle' \
  --handoff-summary-path /tmp/run/health/evidence-20260403/summary.txt \
  --handoff-manifest-path /tmp/release/rc-20260403/manifest.txt \
  --summary-generated-at ' 2026-04-03T06:11:00Z' \
  --manifest-generated-at 2026-04-03T06:12:00Z \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected leading whitespace in summary_generated_at to fail" >&2
  exit 1
fi
grep -q 'invalid --summary-generated-at: must not start or end with whitespace' /tmp/emit-packet.err

if bash "$SCRIPT" \
  --cutover-kind dr_rebuild \
  --verified-worktree /tmp/trnm-lane \
  --verified-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --verified-head 0123456789abcdef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  --handoff-signed-by alice \
  --handoff-acknowledged-by bob \
  --dr-summary-path /tmp/run/bft-restart-recovery-1.txt \
  --dr-generated-at 2026-04-03T06:14:00Z \
  --dr-status ' PASS' \
  --dr-replay-command './scripts/check_bft_restart_recovery.sh --config /tmp/configs/validator-new.json' \
  --dr-rollback-command 'rm -rf /tmp/run/bft-restart-recovery-1.txt' \
  --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle \
  --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --lane-verify-command './scripts/v2/verify_lane_worktree.sh --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle' \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected leading whitespace in dr_status to fail" >&2
  exit 1
fi
grep -q 'invalid --dr-status: must not start or end with whitespace' /tmp/emit-packet.err

bash "$SCRIPT" \
  "${common_args[@]}" \
  --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle \
  --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --lane-verify-command './scripts/v2/verify_lane_worktree.sh --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle' \
  --handoff-summary-path /tmp/run/health/evidence-20260403/summary.txt \
  --handoff-manifest-path /tmp/release/rc-20260403/manifest.txt \
  --summary-generated-at 2026-04-03T06:11:00Z \
  --manifest-generated-at 2026-04-03T06:12:00Z \
  >/tmp/emit-packet.out

grep -q '^expected_worktree_root=/Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle$' /tmp/emit-packet.out
grep -q '^handoff_summary_path=/tmp/run/health/evidence-20260403/summary.txt$' /tmp/emit-packet.out
grep -q '^manifest_generated_at=2026-04-03T06:12:00Z$' /tmp/emit-packet.out
grep -q '^dr_status=PASS$' /tmp/emit-packet.out

echo "PASS"
