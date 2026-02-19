#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
P1_DIR="${P1_DIR:-$ROOT/data/p1-negative}"
RUN_DIR="${RUN_DIR:-$(ls -1dt "$P1_DIR"/* 2>/dev/null | head -n 1 || true)}"
OUT_BASE="${OUT_BASE:-$ROOT/data/verifier-input}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="$OUT_BASE/$TS"

if [[ -z "$RUN_DIR" || ! -d "$RUN_DIR" ]]; then
  echo "[ERR] no p1 run dir found under: $P1_DIR" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
count=0

for logf in "$RUN_DIR"/*.log; do
  [[ -f "$logf" ]] || continue
  while IFS= read -r line; do
    json="${line#*] }"
    trace_id="$(python3 - <<PY
import json
obj=json.loads('''$json''')
print(obj.get('trace_id','unknown'))
PY
)"
    out="$OUT_DIR/${trace_id}.json"
    printf '%s\n' "$json" > "$out"
    count=$((count+1))
  done < <(grep -E '^\[VERIFIER_INPUT\] ' "$logf" || true)
done

summary="$OUT_DIR/summary.txt"
{
  echo "source_run_dir=$RUN_DIR"
  echo "output_dir=$OUT_DIR"
  echo "exported_count=$count"
  ls -1 "$OUT_DIR"/*.json 2>/dev/null || true
} > "$summary"

cat "$summary"

if [[ "$count" -eq 0 ]]; then
  echo "[WARN] no verifier input markers found. Re-run p1 suite after scenario marker update." >&2
  exit 2
fi
