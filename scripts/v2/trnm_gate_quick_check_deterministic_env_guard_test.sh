#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/trnm-gate-quick-check.yml"

if [[ ! -f "$WF" ]]; then
  echo "[FAIL] missing workflow: $WF" >&2
  exit 1
fi

required_lines=(
  'TZ: UTC'
  'LANG: C.UTF-8'
  'LC_ALL: C.UTF-8'
  'LC_NUMERIC: C'
  'LC_COLLATE: C'
  'LC_TIME: C'
  'LC_CTYPE: C'
  'LC_MESSAGES: C'
  'LC_MONETARY: C'
  'LC_MEASUREMENT: C'
  'LC_PAPER: C'
  'LC_ADDRESS: C'
  'LC_NAME: C'
  'LC_TELEPHONE: C'
  'PYTHONHASHSEED: "0"'
  'PYTHONDONTWRITEBYTECODE: "1"'
  'CI: "true"'
  'PYTHONIOENCODING: "UTF-8"'
  'PYTHONUTF8: "1"'
  'PYTHONUNBUFFERED: "1"'
  'PYTHONNOUSERSITE: "1"'
  'PIP_DISABLE_PIP_VERSION_CHECK: "1"'
  'SOURCE_DATE_EPOCH: "1704067200"'
  'GZIP: "-n"'
  'UMASK: "022"'
  'timeout-minutes: 60'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$WF"; then
    echo "[FAIL] missing deterministic quick-check guard: $line" >&2
    exit 1
  fi
done

echo "[PASS] trnm-gate-quick-check keeps deterministic env + timeout guards"
