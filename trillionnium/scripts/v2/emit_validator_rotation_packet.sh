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
  [--operator-ack <text>] \
  [--operator-ack-signature-path <path>] \
  [--handoff-summary-path <path>] \
  [--handoff-manifest-path <path>] \
  [--summary-generated-at <timestamp>] \
  [--manifest-generated-at <timestamp>] \
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
OPERATOR_ACK=""
OPERATOR_ACK_SIGNATURE_PATH=""
HANDOFF_SUMMARY_PATH=""
HANDOFF_MANIFEST_PATH=""
SUMMARY_GENERATED_AT=""
MANIFEST_GENERATED_AT=""
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

require_atom_value() {
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

canonicalize_branch_ref() {
  local ref="$1"
  case "$ref" in
    refs/*)
      printf '%s' "$ref"
      ;;
    *)
      printf 'refs/heads/%s' "$ref"
      ;;
  esac
}

normalize_path() {
  local value="$1"
  python3 - "$value" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
}

path_resolves_under_root() {
  local path_value="$1"
  local root_value="$2"
  local path_canonical
  local root_canonical

  path_canonical="$(normalize_path "$path_value")"
  root_canonical="$(normalize_path "$root_value")"

  python3 - "$path_canonical" "$root_canonical" <<'PY'
import os
import sys

path_value, root_value = sys.argv[1:3]
try:
    common = os.path.commonpath([path_value, root_value])
except ValueError:
    sys.exit(1)

sys.exit(0 if common == root_value else 1)
PY
}

command_has_flag_value() {
  local command="$1"
  local flag_name="$2"
  local expected_value="$3"

  python3 - "$command" "$flag_name" "$expected_value" <<'PY'
import shlex
import sys

command, flag_name, expected_value = sys.argv[1:4]
try:
    tokens = shlex.split(command)
except ValueError:
    sys.exit(1)

for i, token in enumerate(tokens[:-1]):
    if token == flag_name and tokens[i + 1] == expected_value:
        sys.exit(0)

sys.exit(1)
PY
}

command_has_equivalent_branch_ref() {
  local command="$1"
  local flag_name="$2"
  local expected_value="$3"
  local expected_canonical

  expected_canonical="$(canonicalize_branch_ref "$expected_value")"

  python3 - "$command" "$flag_name" "$expected_canonical" <<'PY'
import shlex
import sys

command, flag_name, expected_canonical = sys.argv[1:4]
try:
    tokens = shlex.split(command)
except ValueError:
    sys.exit(1)

for i, token in enumerate(tokens[:-1]):
    if token != flag_name:
        continue
    candidate = tokens[i + 1]
    if not candidate.startswith("refs/"):
        candidate = f"refs/heads/{candidate}"
    if candidate == expected_canonical:
        sys.exit(0)

sys.exit(1)
PY
}

command_mentions_token() {
  local command="$1"
  local expected_token="$2"

  python3 - "$command" "$expected_token" <<'PY'
import shlex
import sys

command, expected_token = sys.argv[1:3]
try:
    tokens = shlex.split(command)
except ValueError:
    sys.exit(1)

sys.exit(0 if expected_token in tokens else 1)
PY
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
    --operator-ack) OPERATOR_ACK="${2-}"; shift 2 ;;
    --operator-ack-signature-path) OPERATOR_ACK_SIGNATURE_PATH="${2-}"; shift 2 ;;
    --handoff-summary-path) HANDOFF_SUMMARY_PATH="${2-}"; shift 2 ;;
    --handoff-manifest-path) HANDOFF_MANIFEST_PATH="${2-}"; shift 2 ;;
    --summary-generated-at) SUMMARY_GENERATED_AT="${2-}"; shift 2 ;;
    --manifest-generated-at) MANIFEST_GENERATED_AT="${2-}"; shift 2 ;;
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
  if [ -z "$EXPECTED_WORKTREE_ROOT" ] || [ -z "$EXPECTED_BRANCH_REF" ] || [ -z "$LANE_VERIFY_COMMAND" ]; then
    printf 'lane binding requires --expected-worktree-root, --expected-branch-ref, and --lane-verify-command together\n' >&2
    usage
    exit 2
  fi
  require_path_value --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"
  require_token --expected-branch-ref "$EXPECTED_BRANCH_REF"
  require_nonempty --lane-verify-command "$LANE_VERIFY_COMMAND"
  case "$LANE_VERIFY_COMMAND" in
    *"verify_lane_worktree.sh"*) ;;
    *)
      printf 'invalid --lane-verify-command: expected verify_lane_worktree.sh invocation\n' >&2
      exit 2
      ;;
  esac
  if ! command_has_flag_value "$LANE_VERIFY_COMMAND" --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"; then
    printf 'invalid --lane-verify-command: missing --expected-worktree-root %s\n' "$EXPECTED_WORKTREE_ROOT" >&2
    exit 2
  fi
  if ! command_has_equivalent_branch_ref "$LANE_VERIFY_COMMAND" --expected-branch-ref "$EXPECTED_BRANCH_REF"; then
    printf 'invalid --lane-verify-command: missing --expected-branch-ref %s\n' "$EXPECTED_BRANCH_REF" >&2
    exit 2
  fi
  if [ "$VERIFIED_WORKTREE" != "$EXPECTED_WORKTREE_ROOT" ]; then
    printf 'invalid packet: verified_worktree drift, expected %s got %s\n' "$EXPECTED_WORKTREE_ROOT" "$VERIFIED_WORKTREE" >&2
    exit 2
  fi
  if [ "$(canonicalize_branch_ref "$VERIFIED_BRANCH_REF")" != "$(canonicalize_branch_ref "$EXPECTED_BRANCH_REF")" ]; then
    printf 'invalid packet: verified_branch_ref drift, expected %s got %s\n' "$(canonicalize_branch_ref "$EXPECTED_BRANCH_REF")" "$VERIFIED_BRANCH_REF" >&2
    exit 2
  fi
  if [ -n "$EXPECTED_HEAD" ]; then
    require_token --expected-head "$EXPECTED_HEAD"
    if ! command_has_flag_value "$LANE_VERIFY_COMMAND" --expected-head "$EXPECTED_HEAD"; then
      printf 'invalid --lane-verify-command: missing --expected-head %s\n' "$EXPECTED_HEAD" >&2
      exit 2
    fi
    if [ "$VERIFIED_HEAD" != "$EXPECTED_HEAD" ]; then
      printf 'invalid packet: verified_head drift, expected %s got %s\n' "$EXPECTED_HEAD" "$VERIFIED_HEAD" >&2
      exit 2
    fi
  fi
fi

if [ -n "$CONFIG_BUNDLE_CHECK_COMMAND" ] || [ -n "$CONFIG_BUNDLE_CHECK_RESULT" ] || [ -n "$CONFIG_BUNDLE_CHECK_LOG_PATH" ]; then
  require_nonempty --config-bundle-check-command "$CONFIG_BUNDLE_CHECK_COMMAND"
  require_nonempty --config-bundle-check-result "$CONFIG_BUNDLE_CHECK_RESULT"
  if ! command_mentions_token "$CONFIG_BUNDLE_CHECK_COMMAND" "$INCOMING_CONFIG_PATH"; then
    printf 'invalid --config-bundle-check-command: must include incoming config path %s\n' "$INCOMING_CONFIG_PATH" >&2
    exit 2
  fi
fi
if [ -n "$CONFIG_BUNDLE_CHECK_LOG_PATH" ]; then
  require_path_value --config-bundle-check-log-path "$CONFIG_BUNDLE_CHECK_LOG_PATH"
fi

if [ "$CUTOVER_KIND" = "rotation" ] || [ "$CUTOVER_KIND" = "dr_rebuild" ]; then
  require_atom_value --handoff-signed-by "$HANDOFF_SIGNED_BY"
  require_atom_value --handoff-acknowledged-by "$HANDOFF_ACKNOWLEDGED_BY"
  require_nonempty --operator-ack "$OPERATOR_ACK"
fi

if [ -n "$OPERATOR_ACK_SIGNATURE_PATH" ]; then
  require_nonempty --operator-ack "$OPERATOR_ACK"
  require_path_value --operator-ack-signature-path "$OPERATOR_ACK_SIGNATURE_PATH"
fi

if [ -n "$HANDOFF_SUMMARY_PATH" ] || [ -n "$HANDOFF_MANIFEST_PATH" ] || [ -n "$SUMMARY_GENERATED_AT" ] || [ -n "$MANIFEST_GENERATED_AT" ]; then
  require_path_value --handoff-summary-path "$HANDOFF_SUMMARY_PATH"
  require_path_value --handoff-manifest-path "$HANDOFF_MANIFEST_PATH"
  require_atom_value --summary-generated-at "$SUMMARY_GENERATED_AT"
  require_atom_value --manifest-generated-at "$MANIFEST_GENERATED_AT"
fi

if [ -n "$DR_SUMMARY_PATH" ] || [ -n "$DR_GENERATED_AT" ] || [ -n "$DR_STATUS" ] || [ -n "$DR_REPLAY_COMMAND" ] || [ -n "$DR_ROLLBACK_COMMAND" ]; then
  require_path_value --dr-summary-path "$DR_SUMMARY_PATH"
  require_atom_value --dr-generated-at "$DR_GENERATED_AT"
  require_atom_value --dr-status "$DR_STATUS"
  require_nonempty --dr-replay-command "$DR_REPLAY_COMMAND"
  require_nonempty --dr-rollback-command "$DR_ROLLBACK_COMMAND"
  if [ "$DR_STATUS" != "PASS" ]; then
    printf 'invalid --dr-status: expected PASS got %s\n' "$DR_STATUS" >&2
    exit 2
  fi
  if ! path_resolves_under_root "$DR_SUMMARY_PATH" "$VERIFIED_WORKTREE/run"; then
    printf 'invalid --dr-summary-path: must resolve under verified worktree run/ %s\n' "$(normalize_path "$VERIFIED_WORKTREE/run")" >&2
    exit 2
  fi
fi

if [ -n "$HANDOFF_SUMMARY_PATH" ] || [ -n "$HANDOFF_MANIFEST_PATH" ] || [ -n "$SUMMARY_GENERATED_AT" ] || [ -n "$MANIFEST_GENERATED_AT" ]; then
  require_path_value --handoff-summary-path "$HANDOFF_SUMMARY_PATH"
  require_path_value --handoff-manifest-path "$HANDOFF_MANIFEST_PATH"
  require_nonempty --summary-generated-at "$SUMMARY_GENERATED_AT"
  require_nonempty --manifest-generated-at "$MANIFEST_GENERATED_AT"
fi

if [ "$CUTOVER_KIND" = "dr_rebuild" ]; then
  require_path_value --dr-summary-path "$DR_SUMMARY_PATH"
  require_atom_value --dr-generated-at "$DR_GENERATED_AT"
  require_atom_value --dr-status "$DR_STATUS"
  require_nonempty --dr-replay-command "$DR_REPLAY_COMMAND"
  require_nonempty --dr-rollback-command "$DR_ROLLBACK_COMMAND"
  require_path_value --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"
  require_token --expected-branch-ref "$EXPECTED_BRANCH_REF"
  require_nonempty --lane-verify-command "$LANE_VERIFY_COMMAND"
  if [ -n "$EXPECTED_HEAD" ]; then
    require_token --expected-head "$EXPECTED_HEAD"
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
if [ -n "$OPERATOR_ACK" ]; then
  printf 'operator_ack=%s\n' "$OPERATOR_ACK"
fi
if [ -n "$OPERATOR_ACK_SIGNATURE_PATH" ]; then
  printf 'operator_ack_signature_path=%s\n' "$OPERATOR_ACK_SIGNATURE_PATH"
fi
if [ -n "$HANDOFF_SUMMARY_PATH" ]; then
  printf 'handoff_summary_path=%s\n' "$HANDOFF_SUMMARY_PATH"
  printf 'handoff_manifest_path=%s\n' "$HANDOFF_MANIFEST_PATH"
  printf 'summary_generated_at=%s\n' "$SUMMARY_GENERATED_AT"
  printf 'manifest_generated_at=%s\n' "$MANIFEST_GENERATED_AT"
fi
printf 'rollback_command=%s\n' "$ROLLBACK_COMMAND"
if [ -n "$DR_SUMMARY_PATH" ]; then
  printf 'dr_summary_path=%s\n' "$DR_SUMMARY_PATH"
  printf 'dr_generated_at=%s\n' "$DR_GENERATED_AT"
  printf 'dr_status=%s\n' "$DR_STATUS"
  printf 'dr_replay_command=%s\n' "$DR_REPLAY_COMMAND"
  printf 'dr_rollback_command=%s\n' "$DR_ROLLBACK_COMMAND"
fi
