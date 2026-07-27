#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

mkdir -p run

NODE1_BLOCK_MS="${NODE1_BLOCK_MS:-500}"
NODE2_BLOCK_MS="${NODE2_BLOCK_MS:-700}"
NODE3_BLOCK_MS="${NODE3_BLOCK_MS:-900}"
NODE1_MAX_BLOCKS="${NODE1_MAX_BLOCKS:-5}"
NODE2_MAX_BLOCKS="${NODE2_MAX_BLOCKS:-5}"
NODE3_MAX_BLOCKS="${NODE3_MAX_BLOCKS:-5}"

cargo run -p trnm-node --bin trnm-sim -- --config configs/node1.toml --block-ms "$NODE1_BLOCK_MS" --max-blocks "$NODE1_MAX_BLOCKS" > run/node1.log 2>&1 &
PID1=$!
cargo run -p trnm-node --bin trnm-sim -- --config configs/node2.toml --block-ms "$NODE2_BLOCK_MS" --max-blocks "$NODE2_MAX_BLOCKS" > run/node2.log 2>&1 &
PID2=$!
cargo run -p trnm-node --bin trnm-sim -- --config configs/node3.toml --block-ms "$NODE3_BLOCK_MS" --max-blocks "$NODE3_MAX_BLOCKS" > run/node3.log 2>&1 &
PID3=$!

echo "$PID1" > run/node1.pid
echo "$PID2" > run/node2.pid
echo "$PID3" > run/node3.pid

echo "devnet started: node1=$PID1 node2=$PID2 node3=$PID3"
echo "logs: $ROOT/run/node{1,2,3}.log"
