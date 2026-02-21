#!/usr/bin/env bash
set -euo pipefail

# Build a minimal re-exec decision bundle:
# - decision.json
# - resolve-template.txt
# - summary.md

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TASK_ID="${TASK_ID:-${1:-}}"
OUTCOME="${OUTCOME:-${2:-}}"           # match|mismatch
REEXEC_HASH="${REEXEC_HASH:-${3:-}}"   # optional
ORIG_HASH="${ORIG_HASH:-${4:-}}"       # optional
OUT_DIR="${OUT_DIR:-$ROOT/data/reexec-bundles/$(date +%Y%m%d-%H%M%S)-${TASK_ID:-unknown}}"
TRACE_ID="${TRACE_ID:-reexec-$(date +%Y%m%d%H%M%S)}"
REPORT_URI="${REPORT_URI:-}"
REEXEC_ENGINE="${REEXEC_ENGINE:-local-reexec}"
REEXEC_VERSION="${REEXEC_VERSION:-v0.1}"

if [[ -z "$TASK_ID" ]]; then
  echo "usage: $0 <task_id> <match|mismatch> [reexec_hash] [orig_hash]" >&2
  exit 2
fi
if [[ "$OUTCOME" != "match" && "$OUTCOME" != "mismatch" ]]; then
  echo "OUTCOME must be match|mismatch" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

if [[ "$OUTCOME" == "mismatch" ]]; then
  CHALLENGE_SUCCEEDED=true
else
  CHALLENGE_SUCCEEDED=false
fi

FINAL_HASH="$REEXEC_HASH"
if [[ -z "$FINAL_HASH" ]]; then
  FINAL_HASH="$ORIG_HASH"
fi
if [[ -z "$FINAL_HASH" ]]; then
  FINAL_HASH="<final-result-hash>"
fi

MEMO="reexec_report_uri=${REPORT_URI:-n/a};reexec_engine=${REEXEC_ENGINE};reexec_version=${REEXEC_VERSION};trace_id=${TRACE_ID}"

cat > "$OUT_DIR/decision.json" <<EOF
{
  "task_id": "$TASK_ID",
  "reexec_outcome": "$OUTCOME",
  "challenge_succeeded": $CHALLENGE_SUCCEEDED,
  "reexec_result_hash": "${REEXEC_HASH:-}",
  "original_result_hash": "${ORIG_HASH:-}",
  "final_result_hash": "$FINAL_HASH",
  "memo": "$MEMO",
  "trace_id": "$TRACE_ID",
  "reexec_engine": "$REEXEC_ENGINE",
  "reexec_version": "$REEXEC_VERSION",
  "report_uri": "${REPORT_URI:-}"
}
EOF

TRACE_ID="$TRACE_ID" REPORT_URI="$REPORT_URI" REEXEC_ENGINE="$REEXEC_ENGINE" REEXEC_VERSION="$REEXEC_VERSION" \
  "$ROOT/scripts/challenge_reexec_resolve_template.sh" \
  "$TASK_ID" "$OUTCOME" "$REEXEC_HASH" "$ORIG_HASH" > "$OUT_DIR/resolve-template.txt"

cat > "$OUT_DIR/summary.md" <<EOF
# Reexec Bundle Summary

- task_id: $TASK_ID
- reexec_outcome: $OUTCOME
- challenge_succeeded: $CHALLENGE_SUCCEEDED
- final_result_hash: $FINAL_HASH
- trace_id: $TRACE_ID
- out_dir: $OUT_DIR

## Files
- decision.json
- resolve-template.txt
EOF

echo "$OUT_DIR"
