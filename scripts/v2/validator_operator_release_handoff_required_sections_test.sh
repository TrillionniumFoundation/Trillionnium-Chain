#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="$ROOT/docs/release/TRNM_VALIDATOR_OPERATOR_RELEASE_HANDOFF_TEMPLATE_2026-03-26.md"

if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] missing handoff template: $TARGET" >&2
  exit 1
fi

required_lines=(
  'operator_id='
  'window_type=rehearsal|upgrade|rollback|handoff'
  'started_at_utc='
  'worktree_root='
  'workspace_root='
  'branch_ref='
  'head_sha='
  'worktree_status=clean|dirty'
  'binary_sha256='
  'cli_binary_sha256='
  'config_set_id='
  'chain_id='
  'genesis_sha256='
  'validator_count='
  'node1_config_sha256='
  'node4_config_sha256='
  'executor='
  'observer='
  'rollback_owner='
  'release_owner='
  'height_before='
  'height_after='
  'commit_events_observed='
  'apply_error_seen='
  'rollback_seen='
  'operator_ack='
  'operator_ack_signature_path='
  'dr_summary_path='
  'previous_stable_anchor='
  'rollback_entrypoint='
  'rollback_trigger=apply_error|height_stall|config_drift|binary_mismatch|operator_abort'
  'dr_replay_command='
  'dr_rollback_command='
  'window_outcome=pass|blocked|rolled-back'
  'blocker_summary='
  'next_safe_action='
  '字段缺失时，不应把本轮状态描述成 release-ready'
  'trnm-node` 与 `trnm-cli` 必须分别记录'
  '进入 release / rehearsal 窗口前，至少确认：'
  '窗口中要留什么证据'
  'handoff 给下一位 operator / release owner 时，至少附：'
  '若 `window_outcome != pass`，必须再附：'
  '不要使用“release-ready”“validator handoff complete”“upgrade finished”之类表述'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$TARGET"; then
    echo "[FAIL] missing handoff guard line: $line" >&2
    exit 1
  fi
done

echo "[PASS] validator/operator release handoff template keeps fail-closed identity, binary/config binding, DR acknowledgment/replay fields, rollback, and blocked-window guard fields"
