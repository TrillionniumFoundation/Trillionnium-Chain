#!/usr/bin/env bash
set -euo pipefail

# Generate SLO summary report from alpha runner output directory.
#
# Usage:
#   ./tools/alpha_report.sh <run_dir>
# Example:
#   ./tools/alpha_report.sh ../docs/alpha-runs/20260218-120754

RUN_DIR="${1:-}"
[[ -n "$RUN_DIR" ]] || { echo "Usage: $0 <run_dir>" >&2; exit 1; }

SUMMARY_FILE="$RUN_DIR/summary.jsonl"
LOG_FILE="$RUN_DIR/run.log"
OUT_FILE="$RUN_DIR/slo_report.md"

command -v jq >/dev/null 2>&1 || { echo "[ERR] jq not found" >&2; exit 1; }
[[ -f "$SUMMARY_FILE" ]] || { echo "[ERR] summary file not found: $SUMMARY_FILE" >&2; exit 1; }

runs="$(wc -l < "$SUMMARY_FILE" | tr -d ' ')"
ok="$(jq -s '[.[] | select(.status=="ok")] | length' "$SUMMARY_FILE")"
fail="$((runs - ok))"
success_rate="$(awk -v a="$ok" -v b="$runs" 'BEGIN { if (b==0) print "0.00"; else printf "%.2f", (a*100.0)/b }')"

p95_duration="$(jq -s 'map(select(.duration_s != null) | .duration_s) | sort | if length==0 then 0 else .[((length*95/100)|floor)] end' "$SUMMARY_FILE")"

top_failures="$(jq -s 'map(select(.status!="ok") | .reason // "unknown") | group_by(.) | map({reason:.[0], count:length}) | sort_by(-.count) | .[:5]' "$SUMMARY_FILE")"

{
  echo "# Alpha SLO Report"
  echo
  echo "- Run dir: \`$RUN_DIR\`"
  echo "- Summary file: \`$SUMMARY_FILE\`"
  echo "- Log file: \`$LOG_FILE\`"
  echo
  echo "## Headline Metrics"
  echo "- runs: $runs"
  echo "- ok: $ok"
  echo "- fail: $fail"
  echo "- success_rate_pct: $success_rate"
  echo "- p95_duration_s: $p95_duration"
  echo
  echo "## Top Failure Reasons"
  if [[ "$fail" -eq 0 ]]; then
    echo "- none"
  else
    echo "$top_failures" | jq -r '.[] | "- \(.reason): \(.count)"'
  fi
} > "$OUT_FILE"

echo "OK: wrote $OUT_FILE"
