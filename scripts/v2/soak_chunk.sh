#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"
./scripts/run_v1_protocol_gates.sh >/dev/null
./scripts/testnet_preflight.sh >/dev/null
echo "[OK] soak chunk $(date '+%F %T')"
