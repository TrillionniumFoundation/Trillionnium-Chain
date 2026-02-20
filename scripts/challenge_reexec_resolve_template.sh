#!/usr/bin/env bash
set -euo pipefail

# Build a resolve-challenge template from re-exec outcome.
# v0.1: off-chain replay -> on-chain authority writeback template.

TASK_ID="${TASK_ID:-${1:-}}"
OUTCOME="${OUTCOME:-${2:-}}"           # match|mismatch
REEXEC_HASH="${REEXEC_HASH:-${3:-}}"   # optional
ORIG_HASH="${ORIG_HASH:-${4:-}}"       # optional fallback
TRACE_ID="${TRACE_ID:-$(date +%Y%m%d%H%M%S)}"
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

cat <<EOF
# challenge re-exec resolve template (v0.1)
# task_id=${TASK_ID}
# outcome=${OUTCOME}
# challenge_succeeded=${CHALLENGE_SUCCEEDED}
# final_result_hash=${FINAL_HASH}
# trace_id=${TRACE_ID}

# authority writeback command template:
trnm-node tx resolve-challenge "${TASK_ID}" "${CHALLENGE_SUCCEEDED}" "${FINAL_HASH}" "${MEMO}"
EOF
