#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: check_bft_restart_recovery.sh [--help]

Runs the BFT restart-recovery drill against configs/node1.toml.

Environment:
  RUNS                   Number of restart-recovery rehearsal cycles to execute (default: 5)
  EXPECTED_WORKTREE_ROOT Optional fail-closed worktree root; when any EXPECTED_* is set,
                         this and EXPECTED_BRANCH_REF are required and verified
  EXPECTED_BRANCH_REF    Optional fail-closed branch ref; normalized to refs/heads/* and
                         verified when lane binding is enabled
  EXPECTED_HEAD          Optional fail-closed HEAD sha verified when provided

Outputs:
  Writes a PASS report under run/bft-restart-recovery-<timestamp>.txt
  The report includes config_path, replay_command, rollback_command, and resolved git identity fields
  (including git_head_state and git_status_summary for handoff-grade audit context).
EOF
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
  "")
    ;;
  *)
    echo "unexpected argument: $1" >&2
    usage >&2
    exit 64
    ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

GIT_STATUS_SHORT="$(git status --short 2>/dev/null || true)"
if [ -n "$GIT_STATUS_SHORT" ]; then
  printf 'dirty worktree: restart recovery drill requires clean git status --short\n' >&2
  printf '%s\n' "$GIT_STATUS_SHORT" >&2
  exit 65
fi

normalize_branch_ref() {
  case "$1" in
    refs/*) printf '%s\n' "$1" ;;
    *) printf 'refs/heads/%s\n' "$1" ;;
  esac
}

canonicalize_path() {
  local input="$1"
  (
    cd "$input" >/dev/null 2>&1 && pwd -P
  )
}

CONFIG_PATH="configs/node1.toml"
[ -f "$CONFIG_PATH" ] || {
  echo "missing config: $CONFIG_PATH" >&2
  exit 66
}

RUNS="${RUNS:-5}"
case "$RUNS" in
  ''|*[!0-9]*)
    echo "RUNS must be a positive integer, got '$RUNS'" >&2
    exit 64
    ;;
esac
if [ "$RUNS" -lt 1 ]; then
  echo "RUNS must be >= 1, got '$RUNS'" >&2
  exit 64
fi
OUT_DIR="$ROOT/run"
TS="$(date -u +%Y%m%d-%H%M%S)"
REPORT="$OUT_DIR/bft-restart-recovery-$TS.txt"
WAL_DIR="$OUT_DIR/consensus-wal-restart-$TS"
PRE_LOG_GLOB="$OUT_DIR/bft-restart-pre-${TS}-*.log"
POST_LOG_GLOB="$OUT_DIR/bft-restart-post-${TS}-*.log"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_HEAD="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_BRANCH_NAME="$(git branch --show-current 2>/dev/null || true)"
if [ -n "$GIT_BRANCH_NAME" ]; then
  GIT_BRANCH_REF="refs/heads/$GIT_BRANCH_NAME"
  GIT_HEAD_STATE="attached"
else
  GIT_BRANCH_REF="<detached>"
  GIT_HEAD_STATE="detached"
fi
GIT_WORKTREE_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
GIT_WORKTREE_ROOT="$(canonicalize_path "$GIT_WORKTREE_ROOT")" || {
  printf 'current worktree path is not accessible: %s\n' "$GIT_WORKTREE_ROOT" >&2
  exit 67
}
CURRENT_WORKTREE_ENTRY="$(git worktree list --porcelain 2>/dev/null | awk -v target="$GIT_WORKTREE_ROOT" '
  BEGIN { in_match=0 }
  /^worktree / {
    path = substr($0, length("worktree ") + 1)
    in_match = (path == target)
  }
  in_match { print }
  in_match && /^$/ { exit }
' || true)"
if [ -n "$CURRENT_WORKTREE_ENTRY" ]; then
  GIT_WORKTREE_BRANCH_REF="$(printf '%s\n' "$CURRENT_WORKTREE_ENTRY" | awk '/^branch / { print $2; exit }')"
else
  GIT_WORKTREE_BRANCH_REF=""
fi
if [ "$GIT_HEAD_STATE" = "attached" ] && [ -z "$GIT_WORKTREE_BRANCH_REF" ]; then
  echo "attached HEAD is missing git worktree branch binding" >&2
  exit 67
fi
if [ "$GIT_HEAD_STATE" = "attached" ] && [ "$GIT_WORKTREE_BRANCH_REF" != "$GIT_BRANCH_REF" ]; then
  echo "git worktree branch binding mismatch: expected $GIT_BRANCH_REF got ${GIT_WORKTREE_BRANCH_REF:-<missing>}" >&2
  exit 67
fi
GIT_STATUS_SUMMARY="clean"
replay_args=(env RUNS="$RUNS")
REPLAY_COMMAND=""
LANE_VERIFY_COMMAND="<not-run>"
if [ -n "${EXPECTED_WORKTREE_ROOT:-}" ] || [ -n "${EXPECTED_BRANCH_REF:-}" ] || [ -n "${EXPECTED_HEAD:-}" ]; then
  [ -n "${EXPECTED_WORKTREE_ROOT:-}" ] || { echo "lane identity failed: EXPECTED_WORKTREE_ROOT is required when lane binding is enabled" >&2; exit 4; }
  [ -n "${EXPECTED_BRANCH_REF:-}" ] || { echo "lane identity failed: EXPECTED_BRANCH_REF is required when lane binding is enabled" >&2; exit 4; }
  EXPECTED_BRANCH_REF="$(normalize_branch_ref "$EXPECTED_BRANCH_REF")"
  lane_verify_args=(
    --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"
    --expected-branch-ref "$EXPECTED_BRANCH_REF"
  )
  if [ -n "${EXPECTED_HEAD:-}" ]; then
    lane_verify_args+=(--expected-head "$EXPECTED_HEAD")
  fi
  LANE_VERIFY_COMMAND="./scripts/v2/verify_lane_worktree.sh"
  for arg in "${lane_verify_args[@]}"; do
    printf -v quoted_arg '%q' "$arg"
    LANE_VERIFY_COMMAND+=" $quoted_arg"
  done
  ./scripts/v2/verify_lane_worktree.sh "${lane_verify_args[@]}" >/dev/null
fi
if [ -n "${EXPECTED_WORKTREE_ROOT:-}" ]; then
  replay_args+=(EXPECTED_WORKTREE_ROOT="$EXPECTED_WORKTREE_ROOT")
fi
if [ -n "${EXPECTED_BRANCH_REF:-}" ]; then
  EXPECTED_BRANCH_REF="$(normalize_branch_ref "$EXPECTED_BRANCH_REF")"
  replay_args+=(EXPECTED_BRANCH_REF="$EXPECTED_BRANCH_REF")
fi
if [ -n "${EXPECTED_HEAD:-}" ]; then
  replay_args+=(EXPECTED_HEAD="$EXPECTED_HEAD")
fi
replay_args+=(./scripts/check_bft_restart_recovery.sh)
for arg in "${replay_args[@]}"; do
  printf -v quoted_arg '%q' "$arg"
  if [ -n "$REPLAY_COMMAND" ]; then
    REPLAY_COMMAND+=" "
  fi
  REPLAY_COMMAND+="$quoted_arg"
done
ROLLBACK_COMMAND="rm -rf $(printf '%q' "$REPORT") $(printf '%q' "$WAL_DIR") && find $(printf '%q' "$OUT_DIR") -maxdepth 1 -type f \\( -name 'bft-restart-pre-${TS}-*.log' -o -name 'bft-restart-post-${TS}-*.log' \\) -delete"
mkdir -p "$OUT_DIR" "$WAL_DIR"

cleanup_bg_node() {
  if [ -n "${pid:-}" ]; then
    kill -9 "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
    pid=""
  fi
}

pass=0
for i in $(seq 1 "$RUNS"); do
  pre="$OUT_DIR/bft-restart-pre-${TS}-${i}.log"
  post="$OUT_DIR/bft-restart-post-${TS}-${i}.log"

  wal_file="$WAL_DIR/consensus-wal.toml"
  rm -f "$wal_file"

  cargo run -q -p trnm-node --bin trnm-sim -- \
    --config configs/node1.toml \
    --block-ms 30 \
    --max-blocks 50 \
    --demo-tasks 12 \
    --demo-keys 3 \
    --validators 4 \
    --byzantine 1 \
    --bft-max-rounds 3 \
    --bft-fault-rounds 1 \
    --bft-wal-dir "$WAL_DIR" >"$pre" 2>&1 &
  pid=$!
  trap cleanup_bg_node EXIT INT TERM

  for _ in $(seq 1 40); do
    [[ -f "$wal_file" ]] && break
    sleep 0.05
  done
  cleanup_bg_node
  trap - EXIT INT TERM

  if [[ ! -f "$wal_file" ]]; then
    echo "[FAIL] restart recovery did not produce WAL run=$i wal=$wal_file pre=$pre" >&2
    exit 3
  fi

  cargo run -q -p trnm-node --bin trnm-sim -- \
    --config configs/node1.toml \
    --block-ms 5 \
    --max-blocks 3 \
    --demo-tasks 6 \
    --demo-keys 3 \
    --validators 4 \
    --byzantine 1 \
    --bft-max-rounds 3 \
    --bft-fault-rounds 1 \
    --bft-wal-dir "$WAL_DIR" >"$post" 2>&1

  grep -q '^\[bft-recover\] restored height=' "$post"
  grep -q '^\[bft\].*step=Commit' "$post"
  if grep -E '\[tx\] apply_error|rollback=true' "$post" >/dev/null; then
    echo "[FAIL] recovery apply_error/rollback run=$i log=$post" >&2
    exit 2
  fi
  pass=$((pass+1))
done

{
  echo "runs=$RUNS"
  echo "pass=$pass"
  echo "generated_at=$GENERATED_AT"
  echo "config_path=$CONFIG_PATH"
  echo "report=$REPORT"
  echo "wal_dir=$WAL_DIR"
  echo "git_worktree_root=$GIT_WORKTREE_ROOT"
  echo "git_worktree_path=$GIT_WORKTREE_ROOT"
  echo "git_branch=${GIT_BRANCH_NAME:-<detached>}"
  echo "git_branch_ref=$GIT_BRANCH_REF"
  echo "git_worktree_branch_ref=${GIT_WORKTREE_BRANCH_REF:-<detached-or-unbound>}"
  echo "git_worktree_entry_begin"
  printf '%s\n' "$CURRENT_WORKTREE_ENTRY"
  echo "git_worktree_entry_end"
  echo "git_head=$GIT_HEAD"
  echo "git_head_state=$GIT_HEAD_STATE"
  echo "git_status_summary=$GIT_STATUS_SUMMARY"
  echo "expected_worktree_root=${EXPECTED_WORKTREE_ROOT:-<unset>}"
  echo "expected_branch_ref=${EXPECTED_BRANCH_REF:-<unset>}"
  echo "expected_head=${EXPECTED_HEAD:-<unset>}"
  echo "pre_log_glob=$OUT_DIR/bft-restart-pre-${TS}-*.log"
  echo "post_log_glob=$OUT_DIR/bft-restart-post-${TS}-*.log"
  echo "replay_command=$REPLAY_COMMAND"
  echo "lane_verify_command=$LANE_VERIFY_COMMAND"
  echo "rollback_command=$ROLLBACK_COMMAND"
  echo "status=PASS"
} > "$REPORT"

echo "[OK] bft restart recovery passed: $REPORT"
