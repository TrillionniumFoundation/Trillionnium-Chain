#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/v2/emit_validator_rotation_packet.sh"

common_args=(
  --cutover-kind dr_rebuild
  --verified-worktree /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle
  --verified-branch-ref refs/heads/lane/mn05-operator-dr-rotation-lifecycle
  --verified-head 0123456789abcdef
  --outgoing-validator-id validator-old
  --incoming-validator-id validator-new
  --incoming-config-path /tmp/configs/validator-new.json
  --rollback-command 'rm -rf /tmp/cutover-note'
  --handoff-signed-by alice
  --handoff-acknowledged-by bob
  --operator-ack 'alice acknowledged validator-new handoff against the cutover note'
  --dr-summary-path /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle/run/bft-restart-recovery-1.txt
  --dr-generated-at 2026-04-03T06:14:00Z
  --dr-status PASS
  --dr-replay-command './scripts/check_bft_restart_recovery.sh --config /tmp/configs/validator-new.json'
  --dr-rollback-command 'rm -rf /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle/run/bft-restart-recovery-1.txt'
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
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected rotation without operator ack to fail" >&2
  exit 1
fi
grep -q 'missing --operator-ack' /tmp/emit-packet.err

if bash "$SCRIPT" \
  --cutover-kind rotation \
  --verified-worktree /tmp/trnm-lane \
  --verified-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --verified-head 0123456789abcdef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  --handoff-signed-by ' alice' \
  --handoff-acknowledged-by bob \
  --operator-ack 'alice acknowledged validator-new handoff against the cutover note' \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected leading whitespace in handoff_signed_by to fail" >&2
  exit 1
fi
grep -q 'invalid --handoff-signed-by: must not start or end with whitespace' /tmp/emit-packet.err

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
  --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --lane-verify-command 'echo lane verified' \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected non-verify_lane_worktree lane verify command to fail" >&2
  exit 1
fi
grep -q 'invalid --lane-verify-command: expected verify_lane_worktree.sh invocation' /tmp/emit-packet.err

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
  --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --lane-verify-command './scripts/v2/verify_lane_worktree.sh --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle' \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected lane verify command missing branch ref to fail" >&2
  exit 1
fi
grep -q 'invalid --lane-verify-command: missing --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle' /tmp/emit-packet.err

if bash "$SCRIPT" \
  --cutover-kind replacement \
  --verified-worktree /tmp/trnm-lane \
  --verified-branch-ref refs/heads/lane/mn05-operator-dr-rotation-lifecycle \
  --verified-head 0123456789abcdef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle \
  --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --lane-verify-command './scripts/v2/verify_lane_worktree.sh --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle' \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected verified worktree drift to fail" >&2
  exit 1
fi
grep -q 'invalid packet: verified_worktree drift, expected /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle got /tmp/trnm-lane' /tmp/emit-packet.err

if bash "$SCRIPT" \
  --cutover-kind replacement \
  --verified-worktree /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle \
  --verified-branch-ref lane/mn05-different-branch \
  --verified-head 0123456789abcdef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle \
  --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --lane-verify-command './scripts/v2/verify_lane_worktree.sh --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle' \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected verified branch drift to fail" >&2
  exit 1
fi
grep -q 'invalid packet: verified_branch_ref drift, expected refs/heads/lane/mn05-operator-dr-rotation-lifecycle got lane/mn05-different-branch' /tmp/emit-packet.err

if bash "$SCRIPT" \
  --cutover-kind replacement \
  --verified-worktree /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle \
  --verified-branch-ref refs/heads/lane/mn05-operator-dr-rotation-lifecycle \
  --verified-head deadbeefdeadbeef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle \
  --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --expected-head 0123456789abcdef \
  --lane-verify-command './scripts/v2/verify_lane_worktree.sh --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle --expected-head 0123456789abcdef' \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected verified head drift to fail" >&2
  exit 1
fi
grep -q 'invalid packet: verified_head drift, expected 0123456789abcdef got deadbeefdeadbeef' /tmp/emit-packet.err

bash "$SCRIPT" \
  --cutover-kind replacement \
  --verified-worktree /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle \
  --verified-branch-ref refs/heads/lane/mn05-operator-dr-rotation-lifecycle \
  --verified-head 0123456789abcdef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle \
  --expected-branch-ref refs/heads/lane/mn05-operator-dr-rotation-lifecycle \
  --lane-verify-command './scripts/v2/verify_lane_worktree.sh --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle' \
  >/tmp/emit-packet.out

grep -q '^expected_branch_ref=refs/heads/lane/mn05-operator-dr-rotation-lifecycle$' /tmp/emit-packet.out

grep -q '^lane_verify_command=./scripts/v2/verify_lane_worktree.sh --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle$' /tmp/emit-packet.out

if bash "$SCRIPT" \
  --cutover-kind replacement \
  --verified-worktree /tmp/trnm-lane \
  --verified-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --verified-head 0123456789abcdef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  --operator-ack-signature-path /tmp/evidence/operator-ack.txt \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected signature path without operator ack to fail" >&2
  exit 1
fi
grep -q 'missing --operator-ack' /tmp/emit-packet.err

if bash "$SCRIPT" \
  --cutover-kind replacement \
  --verified-worktree /tmp/trnm-lane \
  --verified-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --verified-head 0123456789abcdef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  --config-bundle-check-command 'python3 scripts/v2/check_validator_config_bundle.py /tmp/configs/validator-other.json' \
  --config-bundle-check-result '[OK] validated /tmp/configs/validator-other.json' \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected config bundle evidence for a different incoming config to fail" >&2
  exit 1
fi
grep -q 'invalid --config-bundle-check-command: must include incoming config path /tmp/configs/validator-new.json' /tmp/emit-packet.err

bash "$SCRIPT" \
  --cutover-kind replacement \
  --verified-worktree /tmp/trnm-lane \
  --verified-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --verified-head 0123456789abcdef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  --config-bundle-check-command 'python3 scripts/v2/check_validator_config_bundle.py /tmp/configs/validator-new.json /tmp/configs/validator-peer.json' \
  --config-bundle-check-result '[OK] validated /tmp/configs/validator-new.json + peer bundle' \
  --config-bundle-check-log-path /tmp/run/validator-cutover/config-bundle-check.log \
  >/tmp/emit-packet.out

grep -q '^config_bundle_check_command=python3 scripts/v2/check_validator_config_bundle.py /tmp/configs/validator-new.json /tmp/configs/validator-peer.json$' /tmp/emit-packet.out
grep -q '^config_bundle_check_result=\[OK\] validated /tmp/configs/validator-new.json + peer bundle$' /tmp/emit-packet.out
grep -q '^config_bundle_check_log_path=/tmp/run/validator-cutover/config-bundle-check.log$' /tmp/emit-packet.out

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
  --operator-ack 'alice acknowledged validator-new handoff against the cutover note' \
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
  --operator-ack 'alice acknowledged validator-new handoff against the cutover note' \
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
  --operator-ack 'alice acknowledged validator-new handoff against the cutover note' \
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
  --operator-ack 'alice acknowledged validator-new handoff against the cutover note' \
  --dr-summary-path /tmp/run/bft-restart-recovery-1.txt \
  --dr-generated-at 2026-04-03T06:14:00Z \
  --dr-status PASS \
  --dr-replay-command './scripts/check_bft_restart_recovery.sh --config /tmp/configs/validator-new.json' \
  --dr-rollback-command 'rm -rf /tmp/run/bft-restart-recovery-1.txt' \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected dr summary path outside verified worktree run/ to fail" >&2
  exit 1
fi
grep -Eq 'invalid --dr-summary-path: must resolve under verified worktree run/ .*/tmp/trnm-lane/run' /tmp/emit-packet.err

bash "$SCRIPT" \
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
  --operator-ack 'alice acknowledged validator-new handoff against the cutover note' \
  --handoff-summary-path /tmp/release/summary.txt \
  --handoff-manifest-path /tmp/release/manifest.txt \
  --summary-generated-at 2026-04-04T11:45:00Z \
  --manifest-generated-at 2026-04-04T11:46:00Z \
  >/tmp/emit-packet.out

grep -q '^handoff_summary_path=/tmp/release/summary.txt$' /tmp/emit-packet.out
grep -q '^handoff_manifest_path=/tmp/release/manifest.txt$' /tmp/emit-packet.out
grep -q '^summary_generated_at=2026-04-04T11:45:00Z$' /tmp/emit-packet.out
grep -q '^manifest_generated_at=2026-04-04T11:46:00Z$' /tmp/emit-packet.out
grep -q '^operator_ack=alice acknowledged validator-new handoff against the cutover note$' /tmp/emit-packet.out

bash "$SCRIPT" \
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
  --operator-ack 'alice acknowledged validator-new handoff against the cutover note' \
  --operator-ack-signature-path /tmp/evidence/operator-ack.txt \
  >/tmp/emit-packet.out

grep -q '^operator_ack_signature_path=/tmp/evidence/operator-ack.txt$' /tmp/emit-packet.out

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
  --verified-worktree /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle \
  --verified-branch-ref refs/heads/lane/mn05-operator-dr-rotation-lifecycle \
  --verified-head 0123456789abcdef \
  --outgoing-validator-id validator-old \
  --incoming-validator-id validator-new \
  --incoming-config-path /tmp/configs/validator-new.json \
  --rollback-command 'rm -rf /tmp/cutover-note' \
  --handoff-signed-by alice \
  --handoff-acknowledged-by bob \
  --operator-ack 'alice acknowledged validator-new handoff against the cutover note' \
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

if bash "$SCRIPT" \
  "${common_args[@]}" \
  --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle \
  --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --expected-head 0123456789abcdef \
  --lane-verify-command './scripts/v2/verify_lane_worktree.sh --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle' \
  --handoff-summary-path /tmp/run/health/evidence-20260403/summary.txt \
  --handoff-manifest-path /tmp/release/rc-20260403/manifest.txt \
  --summary-generated-at 2026-04-03T06:11:00Z \
  --manifest-generated-at 2026-04-03T06:12:00Z \
  >/tmp/emit-packet.out 2>/tmp/emit-packet.err; then
  echo "expected lane verify command missing expected head to fail" >&2
  exit 1
fi
grep -q 'invalid --lane-verify-command: missing --expected-head 0123456789abcdef' /tmp/emit-packet.err

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
grep -q '^operator_ack=alice acknowledged validator-new handoff against the cutover note$' /tmp/emit-packet.out
grep -q '^dr_status=PASS$' /tmp/emit-packet.out

bash "$SCRIPT" \
  "${common_args[@]}" \
  --expected-worktree-root /Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle \
  --expected-branch-ref lane/mn05-operator-dr-rotation-lifecycle \
  --expected-head 0123456789abcdef \
  --lane-verify-command './scripts/v2/verify_lane_worktree.sh --expected-worktree-root "/Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle" --expected-branch-ref "lane/mn05-operator-dr-rotation-lifecycle" --expected-head "0123456789abcdef"' \
  --handoff-summary-path /tmp/run/health/evidence-20260403/summary.txt \
  --handoff-manifest-path /tmp/release/rc-20260403/manifest.txt \
  --summary-generated-at 2026-04-03T06:11:00Z \
  --manifest-generated-at 2026-04-03T06:12:00Z \
  >/tmp/emit-packet.out

grep -q '^expected_head=0123456789abcdef$' /tmp/emit-packet.out
grep -q '^lane_verify_command=./scripts/v2/verify_lane_worktree.sh --expected-worktree-root "/Users/qianqi/.openclaw/workspace/trnm-mainnet-lanes/MN05-operator-dr-rotation-lifecycle" --expected-branch-ref "lane/mn05-operator-dr-rotation-lifecycle" --expected-head "0123456789abcdef"$' /tmp/emit-packet.out

echo "PASS"
