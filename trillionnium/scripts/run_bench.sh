#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TXS="${TXS:-20000}"
KEYS="${KEYS:-2000}"

cargo run -p trnm-bench -- --txs "$TXS" --keys "$KEYS"
