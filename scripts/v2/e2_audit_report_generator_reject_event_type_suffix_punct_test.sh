#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
GEN="$ROOT/scripts/v2/audit_report_generator.py"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

cat >"$tmp" <<'LOG'
2026-03-04T11:00:00Z [event] event_schema=v1 event_type=resolve, task_id=t-1 challenger_delta=10 treasury_delta=-10
LOG

report=$(python3 "$GEN" "$tmp")

total=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["summary"]["total_audit_events"])' <<<"$report")
if [[ "$total" != "0" ]]; then
  echo "[FAIL] expected spoofed punctuated event_type to be ignored, got total_audit_events=$total" >&2
  exit 1
fi

events=$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)["audit_log"]))' <<<"$report")
if [[ "$events" != "0" ]]; then
  echo "[FAIL] expected no audit_log entries for punctuated event_type, got=$events" >&2
  exit 1
fi

echo "[PASS] E2 audit generator rejects punctuated event_type spoof (resolve,)"
