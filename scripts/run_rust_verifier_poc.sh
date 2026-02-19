#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFIER_DIR="$ROOT/rust/verifier"
OUT_DIR="${OUT_DIR:-$ROOT/data/rust-verifier-local}"
INPUT_DIR="${INPUT_DIR:-$VERIFIER_DIR/fixtures}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "[ERR] cargo not found. Install Rust toolchain first (https://rustup.rs)." >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

(
  cd "$VERIFIER_DIR"
  cargo run -- batch --input-dir "$INPUT_DIR" --output-dir "$OUT_DIR"
)

echo "[OK] verifier verdicts generated under: $OUT_DIR"
ls -1 "$OUT_DIR"
