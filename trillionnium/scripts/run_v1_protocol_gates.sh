#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

echo '== v1 gate: workspace tests =='
cargo test --workspace -q

echo '== v1 gate: event fields ==' 
./scripts/check_event_fields.sh

echo '== v1 gate: event replay order =='
./scripts/check_event_replay_smoke.sh

echo '== v1 gate: parallel sanity =='
cargo run -q -p trnm-node -- \
  --config configs/node1.toml \
  --block-ms 5 \
  --max-blocks 6 \
  --demo-tasks 8 \
  --demo-keys 3 \
  --parallel-workers 4 | tee run/parallel-sanity.log

if grep -E '\[tx\] apply_error|rollback=true' run/parallel-sanity.log; then
  echo "parallel sanity detected apply_error/rollback" >&2
  exit 2
fi

echo '[OK] run_v1_protocol_gates passed'
