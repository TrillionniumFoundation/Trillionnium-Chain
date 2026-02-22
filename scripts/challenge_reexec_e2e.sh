#!/usr/bin/env bash
set -euo pipefail

# Single-entry re-exec flow (minimal closed loop):
#   bundle -> template -> smoke/verify
#
# Usage:
#   scripts/challenge_reexec_e2e.sh [run_id] [task_id] [match|mismatch] [reexec_hash] [orig_hash]

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_ID="${RUN_ID:-${1:-$(date +%Y%m%d-%H%M%S)}}"
TASK_ID="${TASK_ID:-${2:-task-demo-001}}"
OUTCOME="${OUTCOME:-${3:-mismatch}}"          # match|mismatch
REEXEC_HASH="${REEXEC_HASH:-${4:-0xreexecabc}}"
ORIG_HASH="${ORIG_HASH:-${5:-0xorigin}}"
TRACE_ID="${TRACE_ID:-reexec-${RUN_ID}}"
REPORT_URI="${REPORT_URI:-}"
REEXEC_ENGINE="${REEXEC_ENGINE:-local-reexec}"
REEXEC_VERSION="${REEXEC_VERSION:-v0.1}"

RUN_ROOT="${OUT_DIR:-$ROOT/data/reexec-e2e/$RUN_ID}"
BUNDLE_OUT="$RUN_ROOT/bundle"
TEMPLATE_OUT="$RUN_ROOT/template"
VERIFY_OUT="$RUN_ROOT/verify"
SMOKE_OUT="$RUN_ROOT/smoke"

mkdir -p "$BUNDLE_OUT" "$TEMPLATE_OUT" "$VERIFY_OUT" "$SMOKE_OUT"

if [[ "$OUTCOME" != "match" && "$OUTCOME" != "mismatch" ]]; then
  echo "OUTCOME must be match|mismatch" >&2
  exit 2
fi

# 1) bundle
TRACE_ID="$TRACE_ID" REPORT_URI="$REPORT_URI" REEXEC_ENGINE="$REEXEC_ENGINE" REEXEC_VERSION="$REEXEC_VERSION" \
  OUT_DIR="$BUNDLE_OUT" \
  "$ROOT/scripts/challenge_reexec_bundle.sh" "$TASK_ID" "$OUTCOME" "$REEXEC_HASH" "$ORIG_HASH" >/dev/null

# 2) template (standalone output; should align with bundle copy)
TRACE_ID="$TRACE_ID" REPORT_URI="$REPORT_URI" REEXEC_ENGINE="$REEXEC_ENGINE" REEXEC_VERSION="$REEXEC_VERSION" \
  "$ROOT/scripts/challenge_reexec_resolve_template.sh" "$TASK_ID" "$OUTCOME" "$REEXEC_HASH" "$ORIG_HASH" \
  > "$TEMPLATE_OUT/resolve-template.txt"

# 3) verify (minimal closed-loop assertions)
grep -q '"task_id": '"\"$TASK_ID\"" "$BUNDLE_OUT/decision.json"
grep -q '"reexec_outcome": '"\"$OUTCOME\"" "$BUNDLE_OUT/decision.json"
grep -q 'resolve-challenge' "$BUNDLE_OUT/resolve-template.txt"
grep -q 'resolve-challenge' "$TEMPLATE_OUT/resolve-template.txt"
grep -q "$TASK_ID" "$TEMPLATE_OUT/resolve-template.txt"

if ! cmp -s "$BUNDLE_OUT/resolve-template.txt" "$TEMPLATE_OUT/resolve-template.txt"; then
  echo "[WARN] template mismatch between bundle and standalone generation" | tee "$VERIFY_OUT/warn.txt"
fi

# existing smoke script (unchanged) as capability smoke
env -u OUT_DIR "$ROOT/scripts/challenge_reexec_template_smoke.sh" > "$VERIFY_OUT/smoke.log"
SMOKE_SRC="$(sed -n 's/^\[OK\] challenge reexec bundle smoke: \(.*\) (src=.*)$/\1/p' "$VERIFY_OUT/smoke.log" | tail -n1)"
if [[ -n "$SMOKE_SRC" && -d "$SMOKE_SRC" ]]; then
  cp "$SMOKE_SRC/decision.json" "$SMOKE_OUT/decision.json"
  cp "$SMOKE_SRC/resolve-template.txt" "$SMOKE_OUT/resolve-template.txt"
  cp "$SMOKE_SRC/summary.md" "$SMOKE_OUT/summary.md"
fi

cat > "$RUN_ROOT/README.md" <<EOF
# Challenge Re-exec E2E Run

- run_id: $RUN_ID
- task_id: $TASK_ID
- outcome: $OUTCOME
- trace_id: $TRACE_ID
- run_root: $RUN_ROOT

## Steps
1. bundle -> $BUNDLE_OUT
2. template -> $TEMPLATE_OUT/resolve-template.txt
3. verify -> $VERIFY_OUT
4. smoke -> $SMOKE_OUT

## Key artifacts
- bundle/decision.json
- bundle/resolve-template.txt
- bundle/summary.md
- template/resolve-template.txt
- verify/smoke.log
EOF

echo "$RUN_ROOT"