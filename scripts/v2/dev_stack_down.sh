#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

./scripts/v2/explorer_service_down.sh || true
./scripts/v2/faucet_service_down.sh || true
./scripts/v2/rpc_service_down.sh || true

echo "dev_stack.down=ok"
