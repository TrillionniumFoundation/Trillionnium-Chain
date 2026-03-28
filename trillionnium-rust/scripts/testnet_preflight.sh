#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

export TZ="${TZ:-UTC}"
export LC_ALL="${LC_ALL:-C}"
export LANG="${LANG:-C}"

TS="$(date -u +%Y%m%d-%H%M%S)"
OUT_DIR="$ROOT/run/preflight"
LOG="$OUT_DIR/preflight-$TS.log"
SUMMARY="$OUT_DIR/go-no-go-$TS.txt"
mkdir -p "$OUT_DIR"

GIT_HEAD="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_BRANCH_RAW="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
if [ "$GIT_BRANCH_RAW" = "HEAD" ]; then
  GIT_BRANCH="<detached-HEAD>"
  GIT_HEAD_STATE="detached"
else
  GIT_BRANCH="$GIT_BRANCH_RAW"
  GIT_HEAD_STATE="attached"
fi
GIT_TOPLEVEL="$(git rev-parse --show-toplevel 2>/dev/null || echo unknown)"
GIT_STATUS_SHORT="$(git status --short 2>/dev/null || true)"
if [ -z "$GIT_STATUS_SHORT" ]; then
  GIT_STATUS_SUMMARY="clean"
else
  GIT_STATUS_SUMMARY="dirty"
fi
CURRENT_WORKTREE_ENTRY="$(git worktree list --porcelain 2>/dev/null | awk -v target="$GIT_TOPLEVEL" '
  BEGIN { in_match=0 }
  /^worktree / {
    in_match = ($2 == target)
  }
  in_match { print }
  in_match && /^$/ { exit }
' || true)"
if [ -n "$CURRENT_WORKTREE_ENTRY" ]; then
  CURRENT_WORKTREE_BRANCH_REF="$(printf '%s\n' "$CURRENT_WORKTREE_ENTRY" | awk '/^branch / { print $2; exit }')"
else
  CURRENT_WORKTREE_BRANCH_REF=""
fi
if [ -n "$CURRENT_WORKTREE_BRANCH_REF" ] && [ "$GIT_BRANCH_RAW" != "HEAD" ]; then
  EXPECTED_WORKTREE_BRANCH_REF="refs/heads/$GIT_BRANCH_RAW"
  if [ "$CURRENT_WORKTREE_BRANCH_REF" = "$EXPECTED_WORKTREE_BRANCH_REF" ]; then
    WORKTREE_BRANCH_REF_MATCH="true"
  else
    WORKTREE_BRANCH_REF_MATCH="false"
  fi
else
  EXPECTED_WORKTREE_BRANCH_REF=""
  WORKTREE_BRANCH_REF_MATCH="unknown"
fi
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
TRUTH_SOURCE="$REPO_ROOT/RELEASE_READINESS.md"
EVIDENCE_SCOPE="local_testnet_preflight_not_current_release_ready_claim"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

log "start testnet preflight"
log "git_toplevel=$GIT_TOPLEVEL git_branch=$GIT_BRANCH git_head=$GIT_HEAD git_head_state=$GIT_HEAD_STATE git_worktree_branch_ref=${CURRENT_WORKTREE_BRANCH_REF:-<detached-or-unbound>} git_status_summary=$GIT_STATUS_SUMMARY"

log "check rust toolchain"
command -v cargo >/dev/null
cargo --version | tee -a "$LOG"

log "check configs"
for f in configs/node1.toml configs/node2.toml configs/node3.toml; do
  [[ -f "$f" ]] || { echo "missing $f" | tee -a "$LOG"; exit 1; }
done

log "workspace tests"
cargo test --workspace | tee -a "$LOG"

log "single-node parallel sanity"
cargo run -q -p trnm-node -- \
  --config configs/node1.toml \
  --block-ms 5 \
  --max-blocks 6 \
  --demo-tasks 8 \
  --demo-keys 3 \
  --parallel-workers 4 | tee "$ROOT/run/parallel-sanity.log" | tee -a "$LOG"

if grep -E '\[tx\] apply_error|rollback=true' "$ROOT/run/parallel-sanity.log" >/dev/null; then
  log "parallel sanity failed: apply_error/rollback detected"
  exit 2
fi

if ! grep -q '^\[consensus\] finality_p50_ms=' "$ROOT/run/parallel-sanity.log"; then
  log "parallel sanity failed: missing consensus finality/recovery metrics"
  exit 3
fi

log "devnet + audit"
./scripts/devnet_up.sh | tee -a "$LOG"
sleep 12
./scripts/devnet_down.sh | tee -a "$LOG" || true
./scripts/audit_state_roots.sh | tee -a "$LOG"

latest_audit=$(ls -1dt run/audit/state-root-audit-*.txt | head -n 1)
grep -q 'summary ok=true mismatch=0 missing=0' "$latest_audit"
log "audit pass: $latest_audit"

log "quick benchmark matrix"
TXS=5000 ./scripts/run_bench_matrix.sh | tee -a "$LOG"
TXS=5000 ./scripts/run_bench_mixed_matrix.sh | tee -a "$LOG"
./scripts/executor_profile_report.py | tee -a "$LOG"

latest_bench=$(ls -1dt run/bench/bench-matrix-*.txt | head -n 1)
latest_mixed=$(ls -1dt run/bench/bench-mixed-matrix-*.txt | head -n 1)
latest_profile=$(ls -1dt run/bench/executor-profile-summary-*.txt | head -n 1)

cat > "$SUMMARY" <<EOF
rust_l1_testnet_preflight
status=GO
timestamp=$TS
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
log=$LOG
git_toplevel=$GIT_TOPLEVEL
git_branch=$GIT_BRANCH
git_head=$GIT_HEAD
git_head_state=$GIT_HEAD_STATE
git_status_summary=$GIT_STATUS_SUMMARY
git_worktree_path=$GIT_TOPLEVEL
git_worktree_branch_ref=${CURRENT_WORKTREE_BRANCH_REF:-<detached-or-unbound>}
git_expected_worktree_branch_ref=${EXPECTED_WORKTREE_BRANCH_REF:-<unknown>}
git_worktree_branch_ref_match=$WORKTREE_BRANCH_REF_MATCH
git_worktree_entry_begin
$CURRENT_WORKTREE_ENTRY
git_worktree_entry_end
git_status_short_begin
$GIT_STATUS_SHORT
git_status_short_end
truth_source=$TRUTH_SOURCE
historical_evidence_only=true
evidence_scope=$EVIDENCE_SCOPE
audit=$latest_audit
bench_classic=$latest_bench
bench_mixed=$latest_mixed
executor_profile=$latest_profile
EOF

cp -f "$SUMMARY" "$OUT_DIR/go-no-go-latest.txt"
cp -f "$LOG" "$OUT_DIR/preflight-latest.log"

log "[OK] testnet preflight passed"
log "summary: $SUMMARY"
echo "$LOG"