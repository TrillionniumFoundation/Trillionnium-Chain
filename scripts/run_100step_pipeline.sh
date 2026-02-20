#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
STOP_ON_ERROR=${STOP_ON_ERROR:-1} ROUNDS=${ROUNDS:-1} STEPS_FILE="$ROOT/scripts/auto_relay_100.steps" ./scripts/auto_relay.sh
