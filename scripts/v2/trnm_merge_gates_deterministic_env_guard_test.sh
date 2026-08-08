#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/trnm-merge-gates.yml"

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
  'PYTHONIOENCODING: "UTF-8"'
  'PYTHONUTF8: "1"'
  'PYTHONUNBUFFERED: "1"'
  'PYTHONNOUSERSITE: "1"'
  'PIP_DISABLE_PIP_VERSION_CHECK: "1"'
  'PIP_DEFAULT_TIMEOUT: "60"'
  'PIP_NO_PYTHON_VERSION_WARNING: "1"'
  'PIP_PROGRESS_BAR: "off"'
  'CARGO_TERM_COLOR: never'
  'CARGO_TERM_PROGRESS_WHEN: never'
  'CARGO_INCREMENTAL: "0"'
  'CARGO_NET_RETRY: "5"'
  'CARGO_HTTP_TIMEOUT: "120"'
  'CARGO_NET_GIT_FETCH_WITH_CLI: "true"'
  'CARGO_REGISTRIES_CRATES_IO_PROTOCOL: sparse'
  'CI: "true"'
  'UMASK: "022"'
  'SOURCE_DATE_EPOCH: "1704067200"'
  'timeout-minutes: 120'
  'export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"'
)

required_pipefail_lines=(
  'set -euo pipefail'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$WF"; then
    echo "[FAIL] missing deterministic merge-gates guard: $line" >&2
    exit 1
  fi
done

pipefail_count=$(grep -Fc -- 'set -euo pipefail' "$WF" || true)
if [[ "$pipefail_count" -lt 30 ]]; then
  echo "[FAIL] expected broad pipefail coverage in merge-gates workflow, got count=$pipefail_count" >&2
  exit 1
fi

for line in "${required_pipefail_lines[@]}"; do
  if ! grep -Fq -- "$line" "$WF"; then
    echo "[FAIL] missing pipefail merge-gates guard: $line" >&2
    exit 1
  fi
done

echo "[PASS] trnm-merge-gates keeps deterministic env + timeout guards"
