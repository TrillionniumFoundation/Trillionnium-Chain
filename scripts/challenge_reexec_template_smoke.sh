#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/data/reexec-smoke/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT_DIR"

"$ROOT/scripts/challenge_reexec_resolve_template.sh" \
  "task-demo-001" mismatch \
  "0xreexecabc" "0xorigin" \
  > "$OUT_DIR/resolve-template.txt"

grep -q 'resolve-challenge' "$OUT_DIR/resolve-template.txt"
grep -q 'challenge_succeeded=true' "$OUT_DIR/resolve-template.txt"

echo "[OK] challenge reexec template smoke: $OUT_DIR/resolve-template.txt"
