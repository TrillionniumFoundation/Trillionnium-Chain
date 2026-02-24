#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${1:-scripts}"

if [[ ! -d "$TARGET_DIR" ]]; then
  echo "[quick-gate][FAIL] target directory not found: $TARGET_DIR" >&2
  exit 2
fi

SKIP_SHELLCHECK="${QUICK_GATE_SKIP_SHELLCHECK:-0}"

if [[ "$SKIP_SHELLCHECK" != "1" ]] && ! command -v shellcheck >/dev/null 2>&1; then
  echo "[quick-gate][FAIL] shellcheck not found in PATH (set QUICK_GATE_SKIP_SHELLCHECK=1 for syntax-only local run)" >&2
  exit 2
fi

mapfile -t FILES < <(find "$TARGET_DIR" -type f -name '*.sh' -print | LC_ALL=C sort)

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "[quick-gate][WARN] no shell scripts found under $TARGET_DIR"
  exit 0
fi

echo "[quick-gate] target_dir=$TARGET_DIR"
echo "[quick-gate] script_count=${#FILES[@]}"

for f in "${FILES[@]}"; do
  bash -n "$f"
done

echo "[quick-gate] bash -n passed"

if [[ "$SKIP_SHELLCHECK" == "1" ]]; then
  echo "[quick-gate][WARN] QUICK_GATE_SKIP_SHELLCHECK=1 -> shellcheck skipped"
  exit 0
fi

for f in "${FILES[@]}"; do
  shellcheck -S error "$f"
done

echo "[quick-gate] shellcheck -S error passed"
