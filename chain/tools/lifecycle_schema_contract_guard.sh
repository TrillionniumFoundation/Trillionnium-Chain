#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT_DIR"
go test ./tools -run TestLifecycleSummaryContractAndFixtures -count=1

echo "PASS: lifecycle schema contract guard"
