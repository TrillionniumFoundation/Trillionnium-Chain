#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="${WEB4_PREMERGE_RUN_DIR:-$ROOT/run/web4-premerge-evidence/$TS}"
SUMMARY="$RUN_DIR/summary.md"
mkdir -p "$RUN_DIR"

log() {
  echo "[$(date +%H:%M:%S)] $*"
}

run_step() {
  local name="$1"
  shift
  local logfile="$RUN_DIR/${name}.log"
  log "RUN  $name"
  (
    set -euo pipefail
    "$@"
  ) > >(tee "$logfile") 2>&1
  log "PASS $name"
}

cd "$ROOT"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
HEAD_SHA="$(git rev-parse HEAD)"

# 并 main 前 fail-closed：工作区必须干净，避免证据包与源码状态错配
if [[ -n "$(git status --porcelain)" ]]; then
  echo "[WEB4-PREMERGE][FAIL] working tree is not clean; commit/stash first" >&2
  exit 2
fi

{
  echo "# Web4 pre-main evidence pack"
  echo
  echo "- generated_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- branch: $BRANCH"
  echo "- head: $HEAD_SHA"
  echo "- run_dir: $RUN_DIR"
  echo
  echo "## checks"
} > "$SUMMARY"

run_step cargo_test_workspace bash -lc "cd '$ROOT/trillionnium' && cargo test --workspace"
echo "- cargo test --workspace: PASS" >> "$SUMMARY"

run_step web4_release_aggregate_gate bash -lc "cd '$ROOT' && ./scripts/v2/web4_release_aggregate_gate.sh"
echo "- ./scripts/v2/web4_release_aggregate_gate.sh: PASS" >> "$SUMMARY"

run_step frontend_verify bash -lc "cd '$ROOT/web4-frontend' && npm run lint && npm run typecheck && npm run test --if-present && npm run build"
echo "- web4-frontend verify (lint/typecheck/test/build): PASS" >> "$SUMMARY"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "[WEB4-PREMERGE][FAIL] repository became dirty after checks" >&2
  echo "- post_check_git_clean: FAIL" >> "$SUMMARY"
  exit 3
fi

echo "- post_check_git_clean: PASS" >> "$SUMMARY"

echo
log "PASS all checks"
log "summary=$SUMMARY"
