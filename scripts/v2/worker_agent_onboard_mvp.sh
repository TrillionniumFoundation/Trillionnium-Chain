#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "[1/4] build trnm-cli"
export PATH="/Users/$USER/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
export RUSTC="/Users/$USER/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc"
export CARGO="/Users/$USER/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo"
(
  cd "$ROOT/trillionnium"
  "$CARGO" build -p trnm-cli
) >/tmp/trnm-build-cli.log 2>&1 || {
  echo "[FAIL] build trnm-cli failed. log=/tmp/trnm-build-cli.log" >&2
  exit 2
}

echo "[2/4] readiness check"
TRNM_TX_CLI="$ROOT/trillionnium/target/debug/trnm-cli" REQUIRE_REAL_TX_CLI=1 \
  ./scripts/v2/worker_real_cli_readiness.sh >/tmp/trnm-worker-readiness.out 2>&1 || {
  cat /tmp/trnm-worker-readiness.out >&2
  exit 3
}
cat /tmp/trnm-worker-readiness.out

echo "[3/4] worker receipt gates"
./scripts/v2/run_worker_receipt_gates.sh

echo "[4/4] worker strict real-cli gates"
TRNM_TX_CLI="$ROOT/trillionnium/target/debug/trnm-cli" \
  ./scripts/v2/run_worker_receipt_gates_real_cli.sh

echo "[OK] worker-agent onboarding mvp passed"
