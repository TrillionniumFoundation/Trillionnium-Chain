#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/data/reexec-smoke/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT_DIR"

BUNDLE_DIR="$($ROOT/scripts/challenge_reexec_bundle.sh task-demo-001 mismatch 0xreexecabc 0xorigin)"

# copy for smoke artifact locality
cp "$BUNDLE_DIR/decision.json" "$OUT_DIR/decision.json"
cp "$BUNDLE_DIR/resolve-template.txt" "$OUT_DIR/resolve-template.txt"
cp "$BUNDLE_DIR/summary.md" "$OUT_DIR/summary.md"

grep -q '"challenge_succeeded": true' "$OUT_DIR/decision.json"
grep -q 'resolve-challenge' "$OUT_DIR/resolve-template.txt"
grep -q 'challenge_succeeded=true' "$OUT_DIR/resolve-template.txt"
grep -q 'Reexec Bundle Summary' "$OUT_DIR/summary.md"

echo "[OK] challenge reexec bundle smoke: $OUT_DIR (src=$BUNDLE_DIR)"
