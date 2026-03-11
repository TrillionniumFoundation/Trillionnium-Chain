#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOC="$ROOT/RELEASE_READINESS.md"

required_lines=(
  'env TZ=UTC LC_ALL=C LANG=C SOURCE_DATE_EPOCH=1704067200'
  '同一 gate 至少连续执行 2 次'
  '每轮必须给出单行回滚命令'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq "$line" "$DOC"; then
    echo "[FAIL] missing RC runbook guard phrase: $line" >&2
    exit 1
  fi
done

echo "[PASS] M3 release-readiness template keeps deterministic env + replay/rollback guard clauses"
