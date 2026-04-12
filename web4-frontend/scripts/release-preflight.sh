#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPORT_DIR="$ROOT_DIR/run"
REPORT_FILE="$REPORT_DIR/release-preflight-report.txt"

# Normalize time/locale-sensitive output and ensure the script runs from the
# package root even when invoked directly outside `npm run`.
export TZ=UTC
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

cd "$ROOT_DIR"
mkdir -p "$REPORT_DIR"

{
  echo "[release-preflight] started: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "[release-preflight] root: $ROOT_DIR"

  if [[ "${CI_RUN_E2E:-0}" == "1" ]]; then
    echo "[release-preflight] e2e: enabled via CI_RUN_E2E=1"
    total_steps=6
  else
    echo "[release-preflight] e2e: skipped (set CI_RUN_E2E=1 to enable)"
    total_steps=5
  fi

  echo
  echo "== 1/${total_steps} lint =="
  npm run lint

  echo
  echo "== 2/${total_steps} typecheck =="
  npm run typecheck

  echo
  echo "== 3/${total_steps} test =="
  npm run test

  echo
  echo "== 4/${total_steps} contract =="
  npm run test:contract

  if [[ "${CI_RUN_E2E:-0}" == "1" ]]; then
    echo
    echo "== 5/${total_steps} e2e =="
    npm run --if-present test:e2e
    build_step=6
  else
    build_step=5
  fi

  echo
  echo "== ${build_step}/${total_steps} build =="
  if [[ -d .next ]]; then
    echo "[release-preflight] cleaning previous .next artifacts"
    rm -rf .next
  fi
  npm run build

  echo
  echo "[release-preflight] PASS"
} | tee "$REPORT_FILE"

echo "[release-preflight] report written to: $REPORT_FILE"
