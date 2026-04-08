#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  collect_release_operator_preflight.sh \
    [--operator-id <id>] \
    [--window-type <rehearsal|upgrade|rollback|handoff>] \
    [--change-ticket <id>] \
    [--started-at-utc <rfc3339-utc>] \
    [--binary-path <path>] \
    [--binary-build-command <cmd>] \
    [--cli-binary-path <path>] \
    [--cli-build-command <cmd>] \
    [--config-set-id <id>] \
    [--chain-id <id>] \
    [--genesis-sha256 <sha256-or-placeholder>] \
    [--validator-count <count>] \
    [--seed-mode <static|dynamic|mixed>] \
    [--p2p-allowlist-source <path-or-desc>] \
    [--previous-stable-anchor <commit-or-tag>] \
    [--rollback-entrypoint <path-or-command>] \
    [--expected-worktree-root <abs-path>] \
    [--expected-branch <branch>] \
    [--expected-branch-ref <refs/heads/...>] \
    [--expected-head <commit>]

Prints a fail-closed release/operator preflight record for the current lane worktree.
When expected lane arguments are supplied, this script first calls
scripts/v2/verify_lane_worktree.sh and aborts on mismatch.
EOF
}

ROOT="$(git rev-parse --show-toplevel)"
CANONICAL_ROOT="$(cd "$ROOT" && pwd -P)"
ROOT="$CANONICAL_ROOT"
VERIFY_SCRIPT="$ROOT/scripts/v2/verify_lane_worktree.sh"
DEFAULT_WORKSPACE_ROOT="$ROOT"
if [[ -f "$ROOT/trillionnium/Cargo.toml" ]]; then
  DEFAULT_WORKSPACE_ROOT="$ROOT/trillionnium"
fi
WORKSPACE_ROOT="${WORKSPACE_ROOT:-$DEFAULT_WORKSPACE_ROOT}"
if [[ ! -d "$WORKSPACE_ROOT" ]]; then
  echo "[FAIL] workspace root does not exist: $WORKSPACE_ROOT" >&2
  exit 1
fi
CANONICAL_WORKSPACE_ROOT="$(cd "$WORKSPACE_ROOT" && pwd -P)"
case "$CANONICAL_WORKSPACE_ROOT" in
  "$CANONICAL_ROOT"|"$CANONICAL_ROOT"/*) ;;
  *)
    echo "[FAIL] workspace root escapes worktree root: workspace_root=$CANONICAL_WORKSPACE_ROOT worktree_root=$CANONICAL_ROOT" >&2
    exit 1
    ;;
esac
WORKSPACE_ROOT="$CANONICAL_WORKSPACE_ROOT"

normalize_report_path() {
  local input="$1"
  local base="$2"
  local candidate=""
  local parent=""
  local name=""

  if [[ -z "$input" ]]; then
    printf '%s\n' "$input"
    return 0
  fi

  if [[ "$input" == /* ]]; then
    candidate="$input"
  else
    candidate="$base/$input"
  fi

  parent="$(dirname "$candidate")"
  name="$(basename "$candidate")"
  if [[ -d "$parent" ]]; then
    printf '%s/%s\n' "$(cd "$parent" && pwd -P)" "$name"
  else
    printf '%s\n' "$candidate"
  fi
}

CURRENT_BRANCH=""
CURRENT_HEAD=""
WORKTREE_STATUS=""
OPERATOR_ID="${OPERATOR_ID:-<fill-me>}"
WINDOW_TYPE="${WINDOW_TYPE:-<fill-me>}"
CHANGE_TICKET="${CHANGE_TICKET:-<fill-me>}"
STARTED_AT_UTC="${STARTED_AT_UTC:-<fill-me>}"
BINARY_PATH="${BINARY_PATH:-$WORKSPACE_ROOT/target/debug/trnm-node}"
BINARY_BUILD_COMMAND="${BINARY_BUILD_COMMAND:-cargo build -p trnm-node}"
CLI_BINARY_PATH="${CLI_BINARY_PATH:-$WORKSPACE_ROOT/target/debug/trnm-cli}"
CLI_BUILD_COMMAND="${CLI_BUILD_COMMAND:-cargo build -p trnm-cli}"
CONFIG_SET_ID="${CONFIG_SET_ID:-<fill-me>}"
CHAIN_ID="${CHAIN_ID:-<fill-me>}"
GENESIS_SHA256="${GENESIS_SHA256:-<fill-me>}"
VALIDATOR_COUNT="${VALIDATOR_COUNT:-}"
SEED_MODE="${SEED_MODE:-<fill-me>}"
P2P_ALLOWLIST_SOURCE="${P2P_ALLOWLIST_SOURCE:-<fill-me>}"
PREVIOUS_STABLE_ANCHOR="${PREVIOUS_STABLE_ANCHOR:-<fill-me>}"
ROLLBACK_ENTRYPOINT="${ROLLBACK_ENTRYPOINT:-./scripts/devnet_down.sh}"
EXPECTED_WORKTREE_ROOT=""
EXPECTED_BRANCH=""
EXPECTED_BRANCH_REF=""
EXPECTED_HEAD=""

if [[ -z "$VALIDATOR_COUNT" ]]; then
  VALIDATOR_COUNT="$(find "$WORKSPACE_ROOT/configs" -maxdepth 1 -type f -name 'node*.toml' 2>/dev/null | wc -l | awk '{print $1}')"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator-id)
      OPERATOR_ID="${2:-}"
      shift 2
      ;;
    --window-type)
      WINDOW_TYPE="${2:-}"
      shift 2
      ;;
    --change-ticket)
      CHANGE_TICKET="${2:-}"
      shift 2
      ;;
    --started-at-utc)
      STARTED_AT_UTC="${2:-}"
      shift 2
      ;;
    --binary-path)
      BINARY_PATH="${2:-}"
      shift 2
      ;;
    --binary-build-command)
      BINARY_BUILD_COMMAND="${2:-}"
      shift 2
      ;;
    --cli-binary-path)
      CLI_BINARY_PATH="${2:-}"
      shift 2
      ;;
    --cli-build-command)
      CLI_BUILD_COMMAND="${2:-}"
      shift 2
      ;;
    --config-set-id)
      CONFIG_SET_ID="${2:-}"
      shift 2
      ;;
    --chain-id)
      CHAIN_ID="${2:-}"
      shift 2
      ;;
    --genesis-sha256)
      GENESIS_SHA256="${2:-}"
      shift 2
      ;;
    --validator-count)
      VALIDATOR_COUNT="${2:-}"
      shift 2
      ;;
    --seed-mode)
      SEED_MODE="${2:-}"
      shift 2
      ;;
    --p2p-allowlist-source)
      P2P_ALLOWLIST_SOURCE="${2:-}"
      shift 2
      ;;
    --previous-stable-anchor)
      PREVIOUS_STABLE_ANCHOR="${2:-}"
      shift 2
      ;;
    --rollback-entrypoint)
      ROLLBACK_ENTRYPOINT="${2:-}"
      shift 2
      ;;
    --expected-worktree-root)
      EXPECTED_WORKTREE_ROOT="${2:-}"
      shift 2
      ;;
    --expected-branch)
      EXPECTED_BRANCH="${2:-}"
      shift 2
      ;;
    --expected-branch-ref)
      EXPECTED_BRANCH_REF="${2:-}"
      shift 2
      ;;
    --expected-head)
      EXPECTED_HEAD="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[FAIL] unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -n "$EXPECTED_WORKTREE_ROOT" || -n "$EXPECTED_BRANCH" || -n "$EXPECTED_BRANCH_REF" || -n "$EXPECTED_HEAD" ]]; then
  VERIFY_ARGS=()
  if [[ -n "$EXPECTED_WORKTREE_ROOT" ]]; then
    VERIFY_ARGS+=(--expected-worktree-root "$EXPECTED_WORKTREE_ROOT")
  fi
  if [[ -n "$EXPECTED_BRANCH" && -n "$EXPECTED_BRANCH_REF" ]]; then
    CANONICAL_BRANCH_REF="refs/heads/$EXPECTED_BRANCH"
    if [[ "$EXPECTED_BRANCH_REF" != "$CANONICAL_BRANCH_REF" ]]; then
      echo "[FAIL] expected branch/ref mismatch: branch=$EXPECTED_BRANCH branch_ref=$EXPECTED_BRANCH_REF canonical_ref=$CANONICAL_BRANCH_REF" >&2
      exit 1
    fi
  fi
  if [[ -n "$EXPECTED_BRANCH_REF" ]]; then
    VERIFY_ARGS+=(--expected-branch-ref "$EXPECTED_BRANCH_REF")
  elif [[ -n "$EXPECTED_BRANCH" ]]; then
    VERIFY_ARGS+=(--expected-branch "$EXPECTED_BRANCH")
  fi
  if [[ -n "$EXPECTED_HEAD" ]]; then
    VERIFY_ARGS+=(--expected-head "$EXPECTED_HEAD")
  fi
  "$VERIFY_SCRIPT" "${VERIFY_ARGS[@]}" >/dev/null
fi

CURRENT_BRANCH="$(git branch --show-current)"
CURRENT_HEAD="$(git rev-parse HEAD)"
WORKTREE_STATUS="$(test -z "$(git status --short)" && echo clean || echo dirty)"
BINARY_PATH="$(normalize_report_path "$BINARY_PATH" "$WORKSPACE_ROOT")"
CLI_BINARY_PATH="$(normalize_report_path "$CLI_BINARY_PATH" "$WORKSPACE_ROOT")"
ROLLBACK_ENTRYPOINT="$(normalize_report_path "$ROLLBACK_ENTRYPOINT" "$ROOT")"

if [[ -z "$CURRENT_BRANCH" ]]; then
  echo "[FAIL] detached HEAD is not allowed; check out the lane branch before collecting operator preflight evidence" >&2
  exit 1
fi

printf 'operator_id=%s\n' "$OPERATOR_ID"
printf 'window_type=%s\n' "$WINDOW_TYPE"
printf 'change_ticket=%s\n' "$CHANGE_TICKET"
printf 'started_at_utc=%s\n' "$STARTED_AT_UTC"
printf 'worktree_root=%s\n' "$ROOT"
printf 'workspace_root=%s\n' "$WORKSPACE_ROOT"
printf 'branch=%s\n' "$CURRENT_BRANCH"
printf 'branch_ref=%s\n' "refs/heads/$CURRENT_BRANCH"
printf 'head_sha=%s\n' "$CURRENT_HEAD"
printf 'commit_short=%s\n' "${CURRENT_HEAD:0:9}"
printf 'worktree_status=%s\n' "$WORKTREE_STATUS"
printf 'binary_path=%s\n' "$BINARY_PATH"
printf 'binary_sha256=%s\n' "$(if [[ -x "$BINARY_PATH" ]]; then shasum -a 256 "$BINARY_PATH" | awk '{print $1}'; else printf '<not-built>'; fi)"
printf 'build_command=%s\n' "$BINARY_BUILD_COMMAND"
printf 'cli_binary_path=%s\n' "$CLI_BINARY_PATH"
printf 'cli_binary_sha256=%s\n' "$(if [[ -x "$CLI_BINARY_PATH" ]]; then shasum -a 256 "$CLI_BINARY_PATH" | awk '{print $1}'; else printf '<not-built>'; fi)"
printf 'cli_build_command=%s\n' "$CLI_BUILD_COMMAND"
printf 'config_set_id=%s\n' "$CONFIG_SET_ID"
printf 'chain_id=%s\n' "$CHAIN_ID"
printf 'genesis_sha256=%s\n' "$GENESIS_SHA256"
printf 'validator_count=%s\n' "$VALIDATOR_COUNT"
printf 'seed_mode=%s\n' "$SEED_MODE"
printf 'p2p_allowlist_source=%s\n' "$P2P_ALLOWLIST_SOURCE"
for node in 1 2 3 4; do
  config_path="$WORKSPACE_ROOT/configs/node${node}.toml"
  if [[ -f "$config_path" ]]; then
    config_sha256="$(shasum -a 256 "$config_path" | awk '{print $1}')"
  elif [[ "$VALIDATOR_COUNT" =~ ^[0-9]+$ ]] && (( node > VALIDATOR_COUNT )); then
    config_sha256="<not-used>"
  else
    config_sha256="<not-found>"
  fi
  printf 'node%s_config_sha256=%s\n' "$node" "$config_sha256"
done
printf 'previous_stable_anchor=%s\n' "$PREVIOUS_STABLE_ANCHOR"
printf 'rollback_entrypoint=%s\n' "$ROLLBACK_ENTRYPOINT"
