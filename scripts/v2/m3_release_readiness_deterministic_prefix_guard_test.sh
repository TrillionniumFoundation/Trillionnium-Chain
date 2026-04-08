#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOC="$ROOT/RELEASE_READINESS.md"

required_lines=(
  'env TZ=UTC LC_ALL=C LANG=C SOURCE_DATE_EPOCH=1704067200'
  '同一 gate 至少连续执行 2 次'
  '必须原样保留 `replay_env_trnm_challenge_reexec_entry=` 与 `challenge_reexec_entry=`'
  '必须连同 `truth_source=`、`historical_evidence_only=true`、`evidence_scope=` 一起引用'
  '每轮必须给出单行回滚命令'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq "$line" "$DOC"; then
    echo "[FAIL] missing RC runbook guard phrase: $line" >&2
    exit 1
  fi
done

RC_SCRIPT="$ROOT/trillionnium/scripts/release_rc.sh"
if [[ ! -f "$RC_SCRIPT" ]]; then
  echo "[FAIL] missing RC evidence script: $RC_SCRIPT" >&2
  exit 1
fi

rc_required_lines=(
  'BASE_OUT="$(cd "$BASE_OUT_INPUT" && pwd)"'
  'replay_out_dir="$BASE_OUT"'
  'replay_out_dir=$replay_out_dir'
  'replay_command=$replay_command'
  "ALLOW_MISSING_RESOLVE_EVENT='\${ALLOW_MISSING_RESOLVE_EVENT}'"
  "ALLOW_PARTIAL_EVENT_REPLAY='\${ALLOW_PARTIAL_EVENT_REPLAY}'"
  'rollback_command=$rollback_command'
  'rollback_command="rm -rf $(printf '\''%q'\'' "$OUT")"'
  'rc_out_dir=$RC_OUT_DIR'
  'truth_source=$TRUTH_SOURCE'
  'historical_evidence_only=true'
  'evidence_scope=$EVIDENCE_SCOPE'
  'env_mvp_mode=${MVP_MODE:-prod}'
  'env_allow_missing_resolve_event=${ALLOW_MISSING_RESOLVE_EVENT}'
  'env_allow_partial_event_replay=${ALLOW_PARTIAL_EVENT_REPLAY}'
  'env_txs=${TXS:-5000}'
  'env_threshold_profile=${THRESHOLD_PROFILE:-stage1}'
  'env_tz=${TZ:-<unset>}'
  'env_lc_all=${LC_ALL:-<unset>}'
  'env_lang=${LANG:-<unset>}'
  'env_source_date_epoch=${SOURCE_DATE_EPOCH:-<unset>}'
  'env_cargo_term_color=${CARGO_TERM_COLOR:-<unset>}'
  'env_rust_backtrace=${RUST_BACKTRACE:-<unset>}'
  'env_cargo_build_jobs=${CARGO_BUILD_JOBS:-<unset>}'
  'replay_env_mvp_mode=${MVP_MODE:-prod}'
  'replay_env_allow_missing_resolve_event=${ALLOW_MISSING_RESOLVE_EVENT}'
  'replay_env_allow_partial_event_replay=${ALLOW_PARTIAL_EVENT_REPLAY}'
  'replay_env_txs=${TXS:-5000}'
  'replay_env_threshold_profile=${THRESHOLD_PROFILE:-stage1}'
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

rc_required_exports=(
  'export TZ="${TZ:-$replay_tz}"'
  'export LC_ALL="${LC_ALL:-$replay_lc_all}"'
  'export LANG="${LANG:-$replay_lang}"'
  'export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$replay_source_date_epoch}"'
  'export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-$replay_cargo_term_color}"'
  'export RUST_BACKTRACE="${RUST_BACKTRACE:-$replay_rust_backtrace}"'
  'export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$replay_cargo_build_jobs}"'
)

for line in "${rc_required_exports[@]}"; do
  if ! grep -Fq "$line" "$RC_SCRIPT"; then
    echo "[FAIL] missing RC deterministic env default export: $line" >&2
    exit 1
  fi
done

echo "[PASS] M3 release-readiness template and RC manifest keep deterministic env + replay/rollback guard clauses"
