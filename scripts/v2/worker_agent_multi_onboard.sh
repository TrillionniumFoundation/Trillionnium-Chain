#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

WORKERS="${WORKERS:-3}"
PREFIX="${WORKER_PREFIX:-worker}"
TS="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$ROOT/data/worker-multi-onboard/$TS"
mkdir -p "$RUN_DIR"

echo "[multi-onboard] workers=$WORKERS prefix=$PREFIX run_dir=$RUN_DIR"

ok=0
fail=0

for i in $(seq 1 "$WORKERS"); do
  w="${PREFIX}${i}"
  tag="${TS}-${w}-$$"
  log="$RUN_DIR/${w}.log"
  state="/tmp/trnm-${w}-state-${tag}.json"
  submit="/tmp/trnm-${w}-submits-${tag}.jsonl"
  ack="/tmp/trnm-${w}-acks-${tag}.jsonl"
  verify="/tmp/trnm-${w}-verify-${tag}"

  echo "[run] worker=$w" | tee -a "$log"
  adapter_out="/tmp/trnm-${w}-adapter-${tag}.jsonl"
  if WORKER="$w" PAYLOAD="payload-$w" STATE="$state" SUBMIT_LOG="$submit" ACK_LOG="$ack" VERIFY_DIR="$verify" \
      TRNM_TX_ADAPTER_OUT_LOG="$adapter_out" \
      ./scripts/v2/worker_agent_full_loop.sh >>"$log" 2>&1; then
    echo "[ok] worker=$w" | tee -a "$log"
    ok=$((ok+1))
  else
    echo "[fail] worker=$w log=$log" | tee -a "$log"
    fail=$((fail+1))
  fi

done

summary="$RUN_DIR/summary.md"
cat > "$summary" <<EOF
# Worker Multi-Onboard Summary

- ts: $(date '+%F %T %Z')
- workers: $WORKERS
- ok: $ok
- fail: $fail
- run_dir: $RUN_DIR

## Logs
$(for i in $(seq 1 "$WORKERS"); do echo "- ${PREFIX}${i}.log"; done)
EOF

echo "[summary] $summary"
if [[ "$fail" -gt 0 ]]; then
  echo "[FAIL] multi onboard has failures: $fail" >&2
  exit 1
fi

echo "[OK] worker multi onboard passed ok=$ok fail=$fail"
