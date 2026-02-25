#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

set +e
RUN_DIR="$TMP_DIR/run" TOP_N=0 "$ROOT_DIR/scripts/v2/pr7_topn_summary_gate.sh" >/tmp/pr7-topn-invalid.out 2>&1
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "expected invalid TOP_N to fail" >&2
  cat /tmp/pr7-topn-invalid.out >&2 || true
  exit 1
fi

if ! grep -q '^reason=invalid_top_n$' "$TMP_DIR/run/summary.txt"; then
  echo "expected reason=invalid_top_n" >&2
  cat "$TMP_DIR/run/summary.txt" >&2 || true
  exit 1
fi

echo "[PASS] pr7_topn_summary_gate_invalid_topn_test"
