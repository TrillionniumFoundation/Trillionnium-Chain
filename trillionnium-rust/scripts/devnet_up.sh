#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

mkdir -p run

cargo run -p trnm-node -- --config configs/node1.toml --block-ms 500 --max-blocks 5 > run/node1.log 2>&1 &
PID1=$!
cargo run -p trnm-node -- --config configs/node2.toml --block-ms 700 --max-blocks 5 > run/node2.log 2>&1 &
PID2=$!
cargo run -p trnm-node -- --config configs/node3.toml --block-ms 900 --max-blocks 5 > run/node3.log 2>&1 &
PID3=$!

echo "$PID1" > run/node1.pid
echo "$PID2" > run/node2.pid
echo "$PID3" > run/node3.pid

echo "devnet started: node1=$PID1 node2=$PID2 node3=$PID3"
echo "logs: $ROOT/run/node{1,2,3}.log"
