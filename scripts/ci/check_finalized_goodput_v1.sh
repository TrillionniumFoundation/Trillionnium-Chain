#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
python3 -m py_compile "$ROOT/trillionnium/scripts/measure_finalized_goodput.py"
python3 -m unittest discover -s "$ROOT/tests/performance" -v
printf 'FINALIZED_GOODPUT_V1_OK\n'
