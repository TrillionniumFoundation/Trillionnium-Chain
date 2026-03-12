#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="$ROOT/trillionnium-rust/scripts/run_local_release_evidence.sh"

if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] missing target script: $TARGET" >&2
  exit 1
fi

if ! grep -q 'TRNM_CHALLENGE_REEXEC_ENTRY' "$TARGET"; then
  echo "[FAIL] expected deterministic override env TRNM_CHALLENGE_REEXEC_ENTRY" >&2
  exit 1
fi

if grep -q 'find "\$ROOT/scripts"' "$TARGET" || grep -q 'find "\$repo_root/scripts"' "$TARGET"; then
  echo "[FAIL] nondeterministic find-based entry discovery still present" >&2
  exit 1
fi

if ! grep -q 'BASE_OUT="$(cd "$BASE_OUT_INPUT" && pwd)"' "$TARGET"; then
  echo "[FAIL] expected evidence root to be normalized to an absolute path" >&2
  exit 1
fi

if ! grep -q 'challenge_reexec_entry=' "$TARGET"; then
  echo "[FAIL] expected summary to record resolved challenge reexec entry" >&2
  exit 1
fi

if ! grep -q 'env_trnm_challenge_reexec_entry=' "$TARGET"; then
  echo "[FAIL] expected summary to record effective challenge reexec override env" >&2
  exit 1
fi

if ! grep -q 'replay_env_trnm_challenge_reexec_entry=' "$TARGET"; then
  echo "[FAIL] expected summary to record replay challenge reexec override env" >&2
  exit 1
fi

if ! grep -Fq "TRNM_CHALLENGE_REEXEC_ENTRY='\${replay_challenge_entry}'" "$TARGET"; then
  echo "[FAIL] expected replay_command to pin deterministic challenge reexec entry" >&2
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

echo "[PASS] run_local_release_evidence uses deterministic challenge entry selection, replay pinning, and self-applied env defaults"
