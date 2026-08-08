#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

mkdir -p run
OUT="run/event-replay-smoke.log"
LEGACY_OUT="run/event-replay-smoke-legacy.log"

run_legacy_replay() {
  local output="$1"
  rm -rf run/consensus-wal
  cargo run --locked -q -p trnm-node --features legacy-harness --bin trnm-sim -- \
    --config configs/node1.toml \
    --block-ms 1 \
    --max-blocks 8 \
    --txs-per-block 1 \
    --demo-tasks 1 \
    --demo-keys 1 \
    --parallel-workers 2 > "$output"
}

check_event_sequence() {
  local path="$1"
  local expected_csv="$2"
  local collapse_adjacent="$3"
  python3 - "$path" "$expected_csv" "$collapse_adjacent" <<'PY'
import re
import sys

path, expected_csv, collapse_adjacent = sys.argv[1:]
need = expected_csv.split(',')
seen = []
for line in open(path, encoding='utf-8', errors='ignore'):
    if not line.startswith('[event] '):
        continue
    event_type = re.search(r'(?:^| )event_type=([a-z_]+)(?: |$)', line)
    task_id = re.search(r'(?:^| )task_id=([0-9]+)(?: |$)', line)
    if not event_type or not task_id:
        print('malformed event line=', line.rstrip())
        sys.exit(2)
    if task_id.group(1) != '1001':
        print('unexpected task_id=', task_id.group(1))
        print('line=', line.rstrip())
        sys.exit(2)
    seen.append(event_type.group(1))

observed = seen
if collapse_adjacent == '1':
    observed = []
    for event_type in seen:
        if not observed or observed[-1] != event_type:
            observed.append(event_type)

if observed != need:
    print('event replay mismatch')
    print('expected=', need)
    print('seen=', seen)
    print('observed=', observed)
    sys.exit(2)
PY
}

LEGACY_EVENTS="create,accept,commit,reveal"
CANONICAL_EVENTS="create,accept,commit,reveal,challenge,resolve_approval_staged,resolve"

if [[ "${ALLOW_PARTIAL_EVENT_REPLAY:-0}" == "1" ]]; then
  # The legacy simulator has no authenticated governance bootstrap and can
  # therefore cover only the pre-resolution lifecycle. Keep its historical
  # adjacent-node coalescing solely for explicitly partial local releases.
  run_legacy_replay "$OUT"
  check_event_sequence "$OUT" "$LEGACY_EVENTS" 1
else
  # Strict CI keeps the live scheduler/mempool/WAL integration coverage for
  # the four stable pre-resolution events and requires their raw exact order.
  run_legacy_replay "$LEGACY_OUT"
  check_event_sequence "$LEGACY_OUT" "$LEGACY_EVENTS" 0

  # Strict replay follows the current governance contract: the placeholder
  # resolver is forbidden and terminal resolution requires two distinct
  # authority approvals. The exact test drives real state transitions and the
  # same event formatter while avoiding test-only authority injection into the
  # production-candidate=false legacy simulator.
  cargo test --locked -q -p trnm-node --features legacy-harness --bin trnm-sim \
    tests::canonical_event_replay_uses_two_party_resolve_approval \
    -- --exact --nocapture > "$OUT"
  check_event_sequence "$OUT" "$CANONICAL_EVENTS" 0
fi

echo "[OK] event replay smoke passed: $OUT"
