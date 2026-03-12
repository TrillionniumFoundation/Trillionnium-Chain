#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

replay_tz="UTC"
replay_lc_all="C"
replay_lang="C"
replay_source_date_epoch="1704067200"
replay_cargo_term_color="never"
replay_rust_backtrace="1"
replay_cargo_build_jobs="1"

# Keep RC evidence timestamps/log formatting deterministic across runners/locales.
export TZ="${TZ:-$replay_tz}"
export LC_ALL="${LC_ALL:-$replay_lc_all}"
export LANG="${LANG:-$replay_lang}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$replay_source_date_epoch}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-$replay_cargo_term_color}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-$replay_rust_backtrace}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$replay_cargo_build_jobs}"

# Keep RC directory names aligned with the UTC-based manifest/generated_at fields.
TS="$(date -u +%Y%m%d-%H%M%S)"
BASE_OUT_INPUT="${OUT_DIR:-$ROOT/release}"
mkdir -p "$BASE_OUT_INPUT"
BASE_OUT="$(cd "$BASE_OUT_INPUT" && pwd)"
OUT="$BASE_OUT/rc-$TS"
mkdir -p "$OUT"
RC_OUT_DIR="$OUT"

GIT_HEAD="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
TRUTH_SOURCE="$REPO_ROOT/RELEASE_READINESS.md"
EVIDENCE_SCOPE="local_rc_rehearsal_not_current_release_ready_claim"

echo "[rc] output=$OUT"

RELEASE_MODE="${MVP_MODE:-prod}"

# 0) release guard: nightly green streak
if [ "${SKIP_STREAK_CHECK:-0}" = "1" ]; then
  if [ "${CI:-false}" = "true" ] || [ "$RELEASE_MODE" = "prod" ]; then
    echo "SKIP_STREAK_CHECK=1 is forbidden when CI=true or MVP_MODE=prod" >&2
    exit 11
  fi
  echo "nightly streak check skipped (SKIP_STREAK_CHECK=1, MVP_MODE=$RELEASE_MODE)" | tee "$OUT/nightly-streak.log"
else
  ./scripts/check_nightly_green_streak.sh "${GITHUB_OWNER:-ProfAlexQI}" "${GITHUB_REPO:-TrillionniumChain}" "${REQUIRED_GREEN_STREAK:-3}" | tee "$OUT/nightly-streak.log"
fi

# 1) workspace correctness
cargo test --workspace | tee "$OUT/cargo-test.log"

# 2) state-root audit
NODE1_BLOCK_MS=${NODE1_BLOCK_MS:-400} \
NODE2_BLOCK_MS=${NODE2_BLOCK_MS:-400} \
NODE3_BLOCK_MS=${NODE3_BLOCK_MS:-400} \
NODE1_MAX_BLOCKS=${NODE1_MAX_BLOCKS:-8} \
NODE2_MAX_BLOCKS=${NODE2_MAX_BLOCKS:-8} \
NODE3_MAX_BLOCKS=${NODE3_MAX_BLOCKS:-8} \
./scripts/devnet_up.sh
sleep ${DEVNET_AUDIT_WAIT_SECONDS:-20}
./scripts/devnet_down.sh || true

AUDIT_RETRIES=${AUDIT_RETRIES:-3}
AUDIT_RETRY_SLEEP_SECONDS=${AUDIT_RETRY_SLEEP_SECONDS:-2}
audit_ok=0
for i in $(seq 1 "$AUDIT_RETRIES"); do
  if ./scripts/audit_state_roots.sh | tee "$OUT/state-root-audit.log"; then
    audit_ok=1
    break
  fi
  echo "[rc] state-root audit attempt $i/$AUDIT_RETRIES failed; retrying in ${AUDIT_RETRY_SLEEP_SECONDS}s..." | tee -a "$OUT/state-root-audit.log"
  sleep "$AUDIT_RETRY_SLEEP_SECONDS"
done
if [ "$audit_ok" -ne 1 ]; then
  echo "[rc] state-root audit failed after retries" >&2
  exit 2
fi

# 3) parallel sanity
cargo run -q -p trnm-node -- \
  --config configs/node1.toml \
  --block-ms 5 \
  --max-blocks 6 \
  --demo-tasks 8 \
  --demo-keys 3 \
  --parallel-workers 4 | tee "$OUT/parallel-sanity.log"
if grep -E '\[tx\] apply_error|rollback=true' "$OUT/parallel-sanity.log"; then
  echo "parallel sanity detected apply_error/rollback" >&2
  exit 2
fi

# 4) protocol freeze checks
MVP_MODE=${MVP_MODE:-prod}
case "$MVP_MODE" in
  dev|beta)
    : "${ALLOW_MISSING_RESOLVE_EVENT:=1}"
    : "${ALLOW_PARTIAL_EVENT_REPLAY:=1}"
    ;;
  prod)
    : "${ALLOW_MISSING_RESOLVE_EVENT:=0}"
    : "${ALLOW_PARTIAL_EVENT_REPLAY:=0}"
    ;;
  *)
    echo "unknown MVP_MODE=$MVP_MODE (expected dev|beta|prod)" >&2
    exit 12
    ;;
esac

echo "[rc] validation_mode=$MVP_MODE allow_missing_resolve=$ALLOW_MISSING_RESOLVE_EVENT allow_partial_replay=$ALLOW_PARTIAL_EVENT_REPLAY" | tee "$OUT/validation-mode.log"

ALLOW_MISSING_RESOLVE_EVENT="$ALLOW_MISSING_RESOLVE_EVENT" ./scripts/check_event_fields.sh | tee "$OUT/event-field-check.log"
ALLOW_PARTIAL_EVENT_REPLAY="$ALLOW_PARTIAL_EVENT_REPLAY" ./scripts/check_event_replay_smoke.sh | tee "$OUT/event-replay-smoke.log"

# 5) perf evidence
TXS=${TXS:-5000} ./scripts/run_bench_matrix.sh | tee "$OUT/bench-matrix.log"
TXS=${TXS:-5000} ./scripts/run_bench_mixed_matrix.sh | tee "$OUT/bench-mixed-matrix.log"

# 6) threshold enforcement
THRESHOLD_PROFILE=${THRESHOLD_PROFILE:-stage1} ./scripts/enforce_ci_thresholds.sh | tee "$OUT/threshold-enforcement.log"

# optional build artifact
cargo build --workspace | tee "$OUT/cargo-build.log"

rollback_command="rm -rf $(printf '%q' "$RC_OUT_DIR")"
replay_out_dir="$BASE_OUT"
replay_command="env TZ=$replay_tz LC_ALL=$replay_lc_all LANG=$replay_lang SOURCE_DATE_EPOCH=$replay_source_date_epoch CARGO_TERM_COLOR=$replay_cargo_term_color RUST_BACKTRACE=$replay_rust_backtrace CARGO_BUILD_JOBS=$replay_cargo_build_jobs OUT_DIR='${replay_out_dir}' MVP_MODE='${MVP_MODE:-prod}' TXS='${TXS:-5000}' THRESHOLD_PROFILE='${THRESHOLD_PROFILE:-stage1}' ./scripts/release_rc.sh"

cat > "$OUT/manifest.txt" <<EOF
release_id=rc-$TS
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
workspace=$ROOT
rc_out_dir=$RC_OUT_DIR
git_branch=$GIT_BRANCH
git_head=$GIT_HEAD
truth_source=$TRUTH_SOURCE
historical_evidence_only=true
evidence_scope=$EVIDENCE_SCOPE
threshold_profile=${THRESHOLD_PROFILE:-stage1}
txs=${TXS:-5000}
env_mvp_mode=${MVP_MODE:-prod}
env_txs=${TXS:-5000}
env_threshold_profile=${THRESHOLD_PROFILE:-stage1}
env_tz=${TZ:-<unset>}
env_lc_all=${LC_ALL:-<unset>}
env_lang=${LANG:-<unset>}
env_source_date_epoch=${SOURCE_DATE_EPOCH:-<unset>}
env_cargo_term_color=${CARGO_TERM_COLOR:-<unset>}
env_rust_backtrace=${RUST_BACKTRACE:-<unset>}
env_cargo_build_jobs=${CARGO_BUILD_JOBS:-<unset>}
replay_env_mvp_mode=${MVP_MODE:-prod}
replay_env_txs=${TXS:-5000}
replay_env_threshold_profile=${THRESHOLD_PROFILE:-stage1}
replay_env_tz=$replay_tz
replay_env_lc_all=$replay_lc_all
replay_env_lang=$replay_lang
replay_env_source_date_epoch=$replay_source_date_epoch
replay_env_cargo_term_color=$replay_cargo_term_color
replay_env_rust_backtrace=$replay_rust_backtrace
replay_env_cargo_build_jobs=$replay_cargo_build_jobs
replay_out_dir=$replay_out_dir
replay_command=$replay_command
rollback_command=$rollback_command

required_evidence=
nightly-streak.log
cargo-test.log
state-root-audit.log
parallel-sanity.log
event-field-check.log
event-replay-smoke.log
bench-matrix.log
bench-mixed-matrix.log
threshold-enforcement.log
cargo-build.log
EOF

cp -f configs/node1.toml "$OUT/" || true
cp -f configs/node2.toml "$OUT/" || true
cp -f configs/node3.toml "$OUT/" || true

printf '[rc] done\n[rc] manifest=%s\n' "$OUT/manifest.txt"
