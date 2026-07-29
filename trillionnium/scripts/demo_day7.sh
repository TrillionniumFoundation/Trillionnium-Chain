#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p run/day7

./scripts/devnet_up.sh
sleep 2
./scripts/devnet_down.sh || true

# single node deterministic execution demo
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
cargo run -p trnm-node --features legacy-harness --bin trnm-sim -- --config configs/node1.toml --block-ms 20 --max-blocks 10 | tee run/day7/node-demo.log

# grouping benchmark
./scripts/run_bench.sh | tee run/day7/bench.log

echo "[day7-demo] outputs:"
echo "  - run/day7/node-demo.log"
echo "  - run/day7/bench.log"
