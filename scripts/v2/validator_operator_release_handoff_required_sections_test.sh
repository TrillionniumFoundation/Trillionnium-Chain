#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="$ROOT/docs/release/TRNM_VALIDATOR_OPERATOR_RELEASE_HANDOFF_TEMPLATE_2026-03-26.md"

if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] missing handoff template: $TARGET" >&2
  exit 1
fi

required_lines=(
  'worktree_root='
  'workspace_root='
  'branch_ref='
  'head_sha='
  'worktree_status=clean|dirty'
  'binary_sha256='
  'cli_binary_sha256='
  'config_set_id='
  'validator_count='
  'node1_config_sha256='
  'node4_config_sha256='
  'previous_stable_anchor='
  'rollback_entrypoint='
  'rollback_trigger=apply_error|height_stall|config_drift|binary_mismatch|operator_abort'
  'window_outcome=pass|blocked|rolled-back'
  'next_safe_action='
  '字段缺失时，不应把本轮状态描述成 release-ready'
  'trnm-node` 与 `trnm-cli` 必须分别记录'
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

echo "[PASS] validator/operator release handoff template keeps fail-closed identity, binary/config binding, rollback, and blocked-window guard fields"
