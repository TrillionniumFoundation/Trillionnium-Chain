#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUST_ROOT="$ROOT/trillionnium"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/rollback_phasea.sh <target-commit-or-tag> [--yes]

Description:
  One-command rollback helper for Agent↔User Phase A:
    1) switch code to target commit/tag (detached HEAD)
    2) cleanup runtime state/process leftovers
    3) run minimal verification (phaseA gate smoke)

Options:
  --yes           Skip interactive confirmation prompt

Env:
  ALLOW_DIRTY=1            Allow rollback with local uncommitted changes (default: block)
  RELIABILITY_STORE=memory|sqlite   Forwarded to phaseA gate
  RELIABILITY_DB_PATH=<path>        Forwarded when sqlite is used
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]]; then
  usage
  exit $([[ $# -lt 1 ]] && echo 2 || echo 0)
fi

TARGET="$1"
shift || true

ASSUME_YES=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) ASSUME_YES=1 ;;
    *)
      echo "[FAIL] unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
  shift
done

cd "$ROOT"

if [[ ! -d .git ]]; then
  echo "[FAIL] not a git repository: $ROOT" >&2
  exit 2
fi

if [[ ! -x "$RUST_ROOT/scripts/run_agent_user_phasea_gate.sh" ]]; then
  echo "[FAIL] missing gate script: $RUST_ROOT/scripts/run_agent_user_phasea_gate.sh" >&2
  exit 2
fi

if [[ "${ALLOW_DIRTY:-0}" != "1" ]]; then
  if [[ -n "$(git status --porcelain)" ]]; then
    echo "[FAIL] working tree is dirty. commit/stash first, or set ALLOW_DIRTY=1 to override." >&2
    git status --short >&2
    exit 3
  fi
fi

if ! RESOLVED_COMMIT="$(git rev-parse --verify --quiet "${TARGET}^{commit}")"; then
  echo "[FAIL] target not found (commit/tag): $TARGET" >&2
  exit 4
fi

CURRENT_REF="$(git rev-parse --abbrev-ref HEAD || true)"
CURRENT_COMMIT="$(git rev-parse --short HEAD || true)"
TARGET_SUBJECT="$(git show -s --format='%s' "$RESOLVED_COMMIT")"

cat <<EOF
[rollback-phaseA] repo=$ROOT
[rollback-phaseA] current_ref=$CURRENT_REF
[rollback-phaseA] current_commit=$CURRENT_COMMIT
[rollback-phaseA] target_input=$TARGET
[rollback-phaseA] target_commit=$RESOLVED_COMMIT
[rollback-phaseA] target_subject=$TARGET_SUBJECT

This will:
  - checkout target commit in DETACHED HEAD mode
  - stop/clean known runtime leftovers
  - run phaseA gate smoke
EOF

if [[ "$ASSUME_YES" != "1" ]]; then
  printf "Type 'ROLLBACK' to continue: "
  read -r ans
  if [[ "$ans" != "ROLLBACK" ]]; then
    echo "[abort] confirmation not matched"
    exit 5
  fi
fi

TS="$(date +%Y%m%d-%H%M%S)"
RUN_ROOT="$ROOT/run/rollback-phasea/$TS"
mkdir -p "$RUN_ROOT"
LOG="$RUN_ROOT/rollback.log"

# shellcheck disable=SC2064
trap 'echo "[rollback-phaseA] failed. see log: $LOG" >&2' ERR

{
  echo "[step 1/3] switch code -> $RESOLVED_COMMIT"
  git checkout --detach "$RESOLVED_COMMIT"
  echo "[ok] now at $(git rev-parse --short HEAD)"

  echo "[step 2/3] cleanup runtime state"

  # best-effort local devnet shutdown
  if [[ -x "$RUST_ROOT/scripts/devnet_down.sh" ]]; then
    (cd "$RUST_ROOT" && ./scripts/devnet_down.sh) || true
  fi

  # best-effort process cleanup for common local components
  pkill -f "trnm-node" 2>/dev/null || true
  pkill -f "trnm-rpc" 2>/dev/null || true
  pkill -f "trnm-worker-agent" 2>/dev/null || true

  # cleanup transient runtime files only (avoid destructive git clean)
  rm -f "$RUST_ROOT/run/message-gateway/requests.jsonl" || true
  rm -f /tmp/trnm-worker-agent-submissions-phasea-*.jsonl || true

  echo "[ok] runtime cleanup done"

  echo "[step 3/3] run phaseA gate smoke"
  PHASEA_OUT_DIR="$RUN_ROOT/agent-user-phasea"
  mkdir -p "$PHASEA_OUT_DIR"

  (
    cd "$RUST_ROOT"
    OUT_DIR="$PHASEA_OUT_DIR" \
    RELIABILITY_STORE="${RELIABILITY_STORE:-memory}" \
    RELIABILITY_DB_PATH="${RELIABILITY_DB_PATH:-$PHASEA_OUT_DIR/reliability-phasea.sqlite}" \
      ./scripts/run_agent_user_phasea_gate.sh
  )

  echo "[OK] rollback + phaseA smoke passed"
  echo "[artifact] run_root=$RUN_ROOT"
  echo "[artifact] log=$LOG"
} | tee "$LOG"

echo "[done] rollback_phasea completed successfully"
