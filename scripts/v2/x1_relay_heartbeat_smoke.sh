#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT/trillionnium"

cargo test -p trnm-bridge-poc --test x1_relay_heartbeat relay_heartbeat_smoke_reports_heights_and_latency -- --nocapture
