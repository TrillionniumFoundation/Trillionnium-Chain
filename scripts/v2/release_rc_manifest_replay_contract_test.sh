#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET="$ROOT/trillionnium/scripts/release_rc.sh"

if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] missing target script: $TARGET" >&2
  exit 1
fi

required_exports=(
  'export TZ="${TZ:-$replay_tz}"'
  'export LC_ALL="${LC_ALL:-$replay_lc_all}"'
  'export LANG="${LANG:-$replay_lang}"'
  'export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$replay_source_date_epoch}"'
  'export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-$replay_cargo_term_color}"'
  'export RUST_BACKTRACE="${RUST_BACKTRACE:-$replay_rust_backtrace}"'
  'export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$replay_cargo_build_jobs}"'
)

for line in "${required_exports[@]}"; do
  if ! grep -Fq "$line" "$TARGET"; then
    echo "[FAIL] expected deterministic env default export: $line" >&2
    exit 1
  fi
done

required_manifest_lines=(
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
  'replay_command=$replay_command'
  'rollback_command=$rollback_command'
)

for line in "${required_manifest_lines[@]}"; do
  if ! grep -Fq "$line" "$TARGET"; then
    echo "[FAIL] expected RC manifest field: $line" >&2
    exit 1
  fi
done

if ! grep -Fq 'replay_command="env TZ=$replay_tz LC_ALL=$replay_lc_all LANG=$replay_lang SOURCE_DATE_EPOCH=$replay_source_date_epoch CARGO_TERM_COLOR=$replay_cargo_term_color RUST_BACKTRACE=$replay_rust_backtrace CARGO_BUILD_JOBS=$replay_cargo_build_jobs' "$TARGET"; then
  echo "[FAIL] expected replay_command to pin deterministic env prefix" >&2
  exit 1
fi

if ! grep -Fq "rollback_command=\"rm -rf \$(printf '%q' \"\$OUT\")\"" "$TARGET"; then
  echo "[FAIL] expected rollback_command to delete only the generated RC directory" >&2
  exit 1
fi

echo "[PASS] release_rc manifest keeps deterministic env, replay command, and rollback contract"