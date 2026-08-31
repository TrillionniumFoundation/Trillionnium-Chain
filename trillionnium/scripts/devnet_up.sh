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

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
if [[ "$TARGET_DIR" != /* ]]; then
  TARGET_DIR="$ROOT/$TARGET_DIR"
fi
cargo build -p trnm-node --features legacy-harness --bin trnm-sim
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
  SIM_BIN="$TARGET_DIR/$CARGO_BUILD_TARGET/debug/trnm-sim"
else
  SIM_BIN="$TARGET_DIR/debug/trnm-sim"
fi
if [[ ! -x "$SIM_BIN" ]]; then
  echo "missing built simulator binary: $SIM_BIN" >&2
  exit 1
fi

"$SIM_BIN" --config configs/node1.toml --block-ms "$NODE1_BLOCK_MS" --max-blocks "$NODE1_MAX_BLOCKS" > run/node1.log 2>&1 &
PID1=$!
"$SIM_BIN" --config configs/node2.toml --block-ms "$NODE2_BLOCK_MS" --max-blocks "$NODE2_MAX_BLOCKS" > run/node2.log 2>&1 &
PID2=$!
"$SIM_BIN" --config configs/node3.toml --block-ms "$NODE3_BLOCK_MS" --max-blocks "$NODE3_MAX_BLOCKS" > run/node3.log 2>&1 &
PID3=$!

echo "$PID1" > run/node1.pid
echo "$PID2" > run/node2.pid
echo "$PID3" > run/node3.pid

echo "devnet started: node1=$PID1 node2=$PID2 node3=$PID3"
echo "logs: $ROOT/run/node{1,2,3}.log"
