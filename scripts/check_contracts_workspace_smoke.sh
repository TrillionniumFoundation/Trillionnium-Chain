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

MANIFEST="$ROOT/contracts-rust/Cargo.toml"
if [[ ! -f "$MANIFEST" ]]; then
  echo "[FAIL] contracts workspace manifest missing: $MANIFEST" >&2
  exit 1
fi

mkdir -p "$ROOT/run/health"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$ROOT/run/health/contracts-workspace-smoke-${TS}.log"

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

run_step "contracts-rust workspace manifest resolves" \
  "$CARGO_BIN" metadata --manifest-path "$MANIFEST" --locked --no-deps --format-version 1

run_step "contracts-rust workspace check" \
  "$CARGO_BIN" check --manifest-path "$MANIFEST" --locked -q

run_step "contracts-rust workspace tests" \
  "$CARGO_BIN" test --manifest-path "$MANIFEST" --locked -q

printf '\n[OK] contracts workspace smoke passed: %s\n' "$OUT" | tee -a "$OUT"
