#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPORT_DIR="$ROOT_DIR/run"
REPORT_FILE="$REPORT_DIR/release-preflight-report.txt"

mkdir -p "$REPORT_DIR"

{
  echo "[release-preflight] started: $(date '+%Y-%m-%d %H:%M:%S %z')"
  echo "[release-preflight] root: $ROOT_DIR"

  echo
  echo "== 1/5 lint =="
  npm run lint

  echo
  echo "== 2/5 typecheck =="
  npm run typecheck

  echo
  echo "== 3/5 test =="
  npm run test

  echo
  echo "== 4/5 contract =="
  npm run test:contract

  echo
  echo "== 5/5 build =="
  if [[ -d .next ]]; then
    echo "[release-preflight] cleaning previous .next artifacts"
    rm -rf .next
  fi
  npm run build

  echo
  echo "[release-preflight] PASS"
} | tee "$REPORT_FILE"

echo "[release-preflight] report written to: $REPORT_FILE"
