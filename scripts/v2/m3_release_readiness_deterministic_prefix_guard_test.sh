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

RC_SCRIPT="$ROOT/trillionnium-rust/scripts/release_rc.sh"
if [[ ! -f "$RC_SCRIPT" ]]; then
  echo "[FAIL] missing RC evidence script: $RC_SCRIPT" >&2
  exit 1
fi

rc_required_lines=(
  'replay_command=$replay_command'
  'rollback_command=$rollback_command'
  'env_tz=${TZ:-<unset>}'
  'env_lc_all=${LC_ALL:-<unset>}'
  'env_lang=${LANG:-<unset>}'
  'env_source_date_epoch=${SOURCE_DATE_EPOCH:-<unset>}'
  'env_cargo_term_color=${CARGO_TERM_COLOR:-<unset>}'
  'env_rust_backtrace=${RUST_BACKTRACE:-<unset>}'
  'env_cargo_build_jobs=${CARGO_BUILD_JOBS:-<unset>}'
  'replay_env_tz=$replay_tz'
  'replay_env_lc_all=$replay_lc_all'
  'replay_env_lang=$replay_lang'
  'replay_env_source_date_epoch=$replay_source_date_epoch'
  'replay_env_cargo_term_color=$replay_cargo_term_color'
  'replay_env_rust_backtrace=$replay_rust_backtrace'
  'replay_env_cargo_build_jobs=$replay_cargo_build_jobs'
)

for line in "${rc_required_lines[@]}"; do
  if ! grep -Fq "$line" "$RC_SCRIPT"; then
    echo "[FAIL] missing RC manifest replay/rollback field: $line" >&2
    exit 1
  fi
done

echo "[PASS] M3 release-readiness template and RC manifest keep deterministic env + replay/rollback guard clauses"
