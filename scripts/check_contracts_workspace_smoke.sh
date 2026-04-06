#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

CARGO_BIN="${CARGO_BIN:-cargo}"
if ! command -v "$CARGO_BIN" >/dev/null 2>&1; then
  echo "[FAIL] cargo binary not found: $CARGO_BIN" >&2
  exit 1
fi

MANIFEST="$ROOT/contracts/Cargo.toml"
if [[ ! -f "$MANIFEST" ]]; then
  echo "[FAIL] contracts workspace manifest missing: $MANIFEST" >&2
  exit 1
fi

CONTRACTS_ROOT="$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$ROOT/contracts")"
mkdir -p "$ROOT/run/health"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$ROOT/run/health/contracts-workspace-smoke-${TS}.log"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/contracts-workspace-smoke}"
CARGO_TARGET_DIR_ABS="$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$CARGO_TARGET_DIR")"
case "$CARGO_TARGET_DIR_ABS" in
  "$CONTRACTS_ROOT"|"$CONTRACTS_ROOT"/*)
    echo "[FAIL] CARGO_TARGET_DIR must stay outside contracts: $CARGO_TARGET_DIR" >&2
    exit 1
    ;;
esac
mkdir -p "$CARGO_TARGET_DIR_ABS"
CARGO_TARGET_DIR="$CARGO_TARGET_DIR_ABS"

run_step() {
  local description="$1"
  shift
  printf '\n[STEP] %s\n' "$description" | tee -a "$OUT"
  if "$@" | tee -a "$OUT"; then
    printf '[OK] %s\n' "$description" | tee -a "$OUT"
  else
    local status=$?
    printf '[FAIL] %s (exit=%s)\n' "$description" "$status" | tee -a "$OUT"
    return "$status"
  fi
}

run_step "contracts workspace manifest resolves" \
  env CARGO_TARGET_DIR="$CARGO_TARGET_DIR" "$CARGO_BIN" metadata --manifest-path "$MANIFEST" --locked --no-deps --format-version 1

run_step "contracts workspace check" \
  env CARGO_TARGET_DIR="$CARGO_TARGET_DIR" "$CARGO_BIN" check --manifest-path "$MANIFEST" --locked -q

run_step "contracts workspace tests" \
  env CARGO_TARGET_DIR="$CARGO_TARGET_DIR" "$CARGO_BIN" test --manifest-path "$MANIFEST" --locked -q

printf '\n[INFO] cargo target dir: %s\n' "$CARGO_TARGET_DIR" | tee -a "$OUT"
printf '[OK] contracts workspace smoke passed: %s\n' "$OUT" | tee -a "$OUT"
