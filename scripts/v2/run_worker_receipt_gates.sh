#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

./scripts/v2/worker_agent_full_loop.sh
./scripts/v2/worker_replay_guard_test.sh
./scripts/v2/worker_failed_receipt_test.sh

echo "[OK] worker receipt gates passed"
