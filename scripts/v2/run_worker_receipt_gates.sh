#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# isolate adapter/state logs to avoid cross-run nonce/replay pollution
RUN_TAG="$(date +%Y%m%d-%H%M%S)-$$"
export TRNM_TX_ADAPTER_OUT_LOG="/tmp/trnm-worker-adapter-${RUN_TAG}.jsonl"
export STATE="/tmp/trnm-worker-state-${RUN_TAG}.json"
export SUBMIT_LOG="/tmp/trnm-worker-submits-${RUN_TAG}.jsonl"
export ACK_LOG="/tmp/trnm-worker-acks-${RUN_TAG}.jsonl"
export EVENT_LOG="/tmp/trnm-worker-events-${RUN_TAG}.jsonl"
export PROGRESS_LOG="/tmp/trnm-worker-progress-${RUN_TAG}.jsonl"
export VERIFY_DIR="/tmp/trnm-worker-verify-${RUN_TAG}"
export TRNM_WORKER_EVENT_LOG="$EVENT_LOG"
export TRNM_WORKER_PROGRESS_LOG="$PROGRESS_LOG"
for p in "$STATE" "$SUBMIT_LOG" "$ACK_LOG" "$EVENT_LOG" "$PROGRESS_LOG" "$VERIFY_DIR"; do
  [[ "$p" == *"$RUN_TAG"* ]] || { echo "[FAIL] non-isolated gate path: $p" >&2; exit 2; }
done
rm -f "$STATE" "$SUBMIT_LOG" "$ACK_LOG" "$EVENT_LOG" "$PROGRESS_LOG"

./scripts/v2/worker_agent_full_loop.sh
./scripts/v2/worker_replay_guard_test.sh
./scripts/v2/worker_failed_receipt_test.sh
./scripts/v2/worker_resume_no_duplicate_test.sh
./scripts/v2/worker_retry_nonce_boundary_test.sh

echo "[OK] worker receipt gates passed out_log=$TRNM_TX_ADAPTER_OUT_LOG run_tag=$RUN_TAG"
