#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"
exec python3 tools/w0-w7-codegen/traceability_gate_regression_test.py
