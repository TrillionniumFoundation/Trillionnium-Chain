#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TS="$(date +%Y%m%d-%H%M%S)"
OUT="release/rc-$TS"
mkdir -p "$OUT"

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

cat > "$OUT/manifest.txt" <<EOF
release_id=rc-$TS
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
workspace=$ROOT
threshold_profile=${THRESHOLD_PROFILE:-stage1}
txs=${TXS:-5000}

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
