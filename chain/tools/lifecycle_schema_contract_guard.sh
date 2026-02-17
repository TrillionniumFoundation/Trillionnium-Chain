#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

bash "$ROOT_DIR/tools/lifecycle_summary_contract_sync_test.sh"
bash "$ROOT_DIR/tools/lifecycle_summary_fixture_consistency_test.sh"

echo "PASS: lifecycle schema contract guard"
