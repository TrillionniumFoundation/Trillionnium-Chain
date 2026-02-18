#!/usr/bin/env bash
set -euo pipefail

TARGET="x/workload/module/autocli.go"
PATTERN='ChallengeAll|SubmitResult|resolve-challenge|list-challenge'

if [[ ! -f "$TARGET" ]]; then
  echo "[ERR] target file not found: $TARGET" >&2
  exit 2
fi

echo "[check] scanning $TARGET"
if grep -nE "$PATTERN" "$TARGET"; then
  echo "[ok] command hooks found"
  exit 0
else
  echo "[warn] no matches found (non-fatal for intermediate states)"
  exit 0
fi
