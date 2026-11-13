#!/usr/bin/env bash
set -euo pipefail
label="$1"
shift
status=0
"$@" 2>&1 | tee "$OUT/$label.log" || status=$?
printf '%s\n' "$status" > "$OUT/$label.exit"
exit "$status"
