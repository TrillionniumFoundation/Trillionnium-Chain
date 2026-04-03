#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF' >&2
Usage: emit_validator_rotation_packet.sh \
  --cutover-kind <replacement|rotation|dr_rebuild> \
  --verified-worktree <path> \
  --verified-branch-ref <ref> \
  --verified-head <sha> \
  --outgoing-validator-id <id> \
  --incoming-validator-id <id> \
  --incoming-config-path <path> \
  --rollback-command <command> \
  [--config-bundle-check-command <command>] \
  [--config-bundle-check-result <result>] \
  [--config-bundle-check-log-path <path>] \
  [--handoff-signed-by <name>] \
  [--handoff-acknowledged-by <name>] \
  [--dr-summary-path <path>] \
  [--dr-generated-at <timestamp>] \
  [--dr-status <PASS>] \
  [--dr-replay-command <command>] \
  [--dr-rollback-command <command>] \
  [--expected-worktree-root <path>] \
  [--expected-branch-ref <ref>] \
  [--expected-head <sha>] \
  [--lane-verify-command <command>]

Emit one canonical replacement/rotation/DR handoff packet block.
This helper is intentionally narrow: it does not perform the cutover or validate
artifacts itself. It only fails closed on missing packet fields so operators do
not hand-assemble notes from shell memory.
EOF
}

CUTOVER_KIND=""
VERIFIED_WORKTREE=""
VERIFIED_BRANCH_REF=""
VERIFIED_HEAD=""
OUTGOING_VALIDATOR_ID=""
INCOMING_VALIDATOR_ID=""
INCOMING_CONFIG_PATH=""
ROLLBACK_COMMAND=""
CONFIG_BUNDLE_CHECK_COMMAND=""
CONFIG_BUNDLE_CHECK_RESULT=""
CONFIG_BUNDLE_CHECK_LOG_PATH=""
HANDOFF_SIGNED_BY=""
HANDOFF_ACKNOWLEDGED_BY=""
DR_SUMMARY_PATH=""
DR_GENERATED_AT=""
DR_STATUS=""
DR_REPLAY_COMMAND=""
DR_ROLLBACK_COMMAND=""
EXPECTED_WORKTREE_ROOT=""
EXPECTED_BRANCH_REF=""
EXPECTED_HEAD=""
LANE_VERIFY_COMMAND=""

require_nonempty() {
  local flag_name="$1"
  local value="$2"
  [ -n "$value" ] || {
    printf 'missing %s\n' "$flag_name" >&2
    usage
    exit 2
  }
}

require_token() {
  local flag_name="$1"
  local value="$2"
  require_nonempty "$flag_name" "$value"
  case "$value" in
    *[[:space:]]*)
      printf 'invalid %s: must not contain whitespace: %s\n' "$flag_name" "$value" >&2
      exit 2
      ;;
  esac
}

require_path_value() {
  local flag_name="$1"
  local value="$2"
  require_nonempty "$flag_name" "$value"
  case "$value" in
    [[:space:]]*|*[[:space:]])
      printf 'invalid %s: must not start or end with whitespace: %q\n' "$flag_name" "$value" >&2
      exit 2
      ;;
  esac
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --cutover-kind) CUTOVER_KIND="${2-}"; shift 2 ;;
    --verified-worktree) VERIFIED_WORKTREE="${2-}"; shift 2 ;;
    --verified-branch-ref) VERIFIED_BRANCH_REF="${2-}"; shift 2 ;;
    --verified-head) VERIFIED_HEAD="${2-}"; shift 2 ;;
    --outgoing-validator-id) OUTGOING_VALIDATOR_ID="${2-}"; shift 2 ;;
    --incoming-validator-id) INCOMING_VALIDATOR_ID="${2-}"; shift 2 ;;
    --incoming-config-path) INCOMING_CONFIG_PATH="${2-}"; shift 2 ;;
    --rollback-command) ROLLBACK_COMMAND="${2-}"; shift 2 ;;
    --config-bundle-check-command) CONFIG_BUNDLE_CHECK_COMMAND="${2-}"; shift 2 ;;
    --config-bundle-check-result) CONFIG_BUNDLE_CHECK_RESULT="${2-}"; shift 2 ;;
    --config-bundle-check-log-path) CONFIG_BUNDLE_CHECK_LOG_PATH="${2-}"; shift 2 ;;
    --handoff-signed-by) HANDOFF_SIGNED_BY="${2-}"; shift 2 ;;
    --handoff-acknowledged-by) HANDOFF_ACKNOWLEDGED_BY="${2-}"; shift 2 ;;
    --dr-summary-path) DR_SUMMARY_PATH="${2-}"; shift 2 ;;
    --dr-generated-at) DR_GENERATED_AT="${2-}"; shift 2 ;;
    --dr-status) DR_STATUS="${2-}"; shift 2 ;;
    --dr-replay-command) DR_REPLAY_COMMAND="${2-}"; shift 2 ;;
    --dr-rollback-command) DR_ROLLBACK_COMMAND="${2-}"; shift 2 ;;
    --expected-worktree-root) EXPECTED_WORKTREE_ROOT="${2-}"; shift 2 ;;
    --expected-branch-ref) EXPECTED_BRANCH_REF="${2-}"; shift 2 ;;
    --expected-head) EXPECTED_HEAD="${2-}"; shift 2 ;;
    --lane-verify-command) LANE_VERIFY_COMMAND="${2-}"; shift 2 ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done

case "$CUTOVER_KIND" in
  replacement|rotation|dr_rebuild) ;;
  *)
    printf 'invalid --cutover-kind: %s\n' "$CUTOVER_KIND" >&2
    usage
    exit 2
    ;;
esac

require_path_value --verified-worktree "$VERIFIED_WORKTREE"
require_token --verified-branch-ref "$VERIFIED_BRANCH_REF"
require_token --verified-head "$VERIFIED_HEAD"
require_token --outgoing-validator-id "$OUTGOING_VALIDATOR_ID"
require_token --incoming-validator-id "$INCOMING_VALIDATOR_ID"
require_path_value --incoming-config-path "$INCOMING_CONFIG_PATH"
require_nonempty --rollback-command "$ROLLBACK_COMMAND"

if [ -n "$EXPECTED_WORKTREE_ROOT" ] || [ -n "$EXPECTED_BRANCH_REF" ] || [ -n "$EXPECTED_HEAD" ] || [ -n "$LANE_VERIFY_COMMAND" ]; then
  require_path_value --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"
  require_token --expected-branch-ref "$EXPECTED_BRANCH_REF"
  require_nonempty --lane-verify-command "$LANE_VERIFY_COMMAND"
  if [ -n "$EXPECTED_HEAD" ]; then
    require_token --expected-head "$EXPECTED_HEAD"
  fi
fi

if [ -n "$CONFIG_BUNDLE_CHECK_COMMAND" ] || [ -n "$CONFIG_BUNDLE_CHECK_RESULT" ] || [ -n "$CONFIG_BUNDLE_CHECK_LOG_PATH" ]; then
  require_nonempty --config-bundle-check-command "$CONFIG_BUNDLE_CHECK_COMMAND"
  require_nonempty --config-bundle-check-result "$CONFIG_BUNDLE_CHECK_RESULT"
fi
if [ -n "$CONFIG_BUNDLE_CHECK_LOG_PATH" ]; then
  require_path_value --config-bundle-check-log-path "$CONFIG_BUNDLE_CHECK_LOG_PATH"
fi

if [ "$CUTOVER_KIND" = "rotation" ] || [ "$CUTOVER_KIND" = "dr_rebuild" ]; then
  require_nonempty --handoff-signed-by "$HANDOFF_SIGNED_BY"
  require_nonempty --handoff-acknowledged-by "$HANDOFF_ACKNOWLEDGED_BY"
fi

if [ "$CUTOVER_KIND" = "dr_rebuild" ]; then
  require_path_value --dr-summary-path "$DR_SUMMARY_PATH"
  require_nonempty --dr-generated-at "$DR_GENERATED_AT"
  require_nonempty --dr-status "$DR_STATUS"
  require_nonempty --dr-replay-command "$DR_REPLAY_COMMAND"
  require_nonempty --dr-rollback-command "$DR_ROLLBACK_COMMAND"
  require_path_value --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"
  require_token --expected-branch-ref "$EXPECTED_BRANCH_REF"
  require_nonempty --lane-verify-command "$LANE_VERIFY_COMMAND"
  if [ -n "$EXPECTED_HEAD" ]; then
    require_token --expected-head "$EXPECTED_HEAD"
  fi
  if [ "$DR_STATUS" != "PASS" ]; then
    printf 'invalid --dr-status: expected PASS got %s\n' "$DR_STATUS" >&2
    exit 2
  fi
fi

printf 'cutover_kind=%s\n' "$CUTOVER_KIND"
printf 'verified_worktree=%s\n' "$VERIFIED_WORKTREE"
printf 'verified_branch_ref=%s\n' "$VERIFIED_BRANCH_REF"
printf 'verified_head=%s\n' "$VERIFIED_HEAD"
printf 'outgoing_validator_id=%s\n' "$OUTGOING_VALIDATOR_ID"
printf 'incoming_validator_id=%s\n' "$INCOMING_VALIDATOR_ID"
printf 'incoming_config_path=%s\n' "$INCOMING_CONFIG_PATH"
if [ -n "$CONFIG_BUNDLE_CHECK_COMMAND" ]; then
  printf 'config_bundle_check_command=%s\n' "$CONFIG_BUNDLE_CHECK_COMMAND"
  printf 'config_bundle_check_result=%s\n' "$CONFIG_BUNDLE_CHECK_RESULT"
fi
if [ -n "$CONFIG_BUNDLE_CHECK_LOG_PATH" ]; then
  printf 'config_bundle_check_log_path=%s\n' "$CONFIG_BUNDLE_CHECK_LOG_PATH"
fi
if [ -n "$EXPECTED_WORKTREE_ROOT" ]; then
  printf 'expected_worktree_root=%s\n' "$EXPECTED_WORKTREE_ROOT"
  printf 'expected_branch_ref=%s\n' "$EXPECTED_BRANCH_REF"
  if [ -n "$EXPECTED_HEAD" ]; then
    printf 'expected_head=%s\n' "$EXPECTED_HEAD"
  fi
  printf 'lane_verify_command=%s\n' "$LANE_VERIFY_COMMAND"
fi
if [ -n "$HANDOFF_SIGNED_BY" ]; then
  printf 'handoff_signed_by=%s\n' "$HANDOFF_SIGNED_BY"
  printf 'handoff_acknowledged_by=%s\n' "$HANDOFF_ACKNOWLEDGED_BY"
fi
printf 'rollback_command=%s\n' "$ROLLBACK_COMMAND"
if [ "$CUTOVER_KIND" = "dr_rebuild" ]; then
  printf 'dr_summary_path=%s\n' "$DR_SUMMARY_PATH"
  printf 'dr_generated_at=%s\n' "$DR_GENERATED_AT"
  printf 'dr_status=%s\n' "$DR_STATUS"
  printf 'dr_replay_command=%s\n' "$DR_REPLAY_COMMAND"
  printf 'dr_rollback_command=%s\n' "$DR_ROLLBACK_COMMAND"
fi
