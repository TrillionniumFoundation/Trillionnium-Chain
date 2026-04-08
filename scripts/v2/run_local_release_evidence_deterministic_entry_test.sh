#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="$ROOT/trillionnium/scripts/run_local_release_evidence.sh"

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

if ! grep -q 'replay_out_dir=' "$TARGET"; then
  echo "[FAIL] expected summary to record normalized replay output root" >&2
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

if ! grep -q 'replay_env_trnm_challenge_reexec_entry=<entry_not_found>' "$TARGET"; then
  echo "[FAIL] expected unresolved replay challenge entry state to use a final explicit sentinel" >&2
  exit 1
fi

if ! grep -q 'challenge_reexec_entry=<entry_not_found>' "$TARGET"; then
  echo "[FAIL] expected unresolved challenge entry state to be written explicitly in the summary header" >&2
  exit 1
fi

if grep -q '<pending_resolution>' "$TARGET"; then
  echo "[FAIL] stale pending-resolution placeholder should not remain in deterministic evidence summary output" >&2
  exit 1
fi

RUNBOOK="$ROOT/trillionnium/docs/runbooks/local-release-evidence.md"
if [[ ! -f "$RUNBOOK" ]]; then
  echo "[FAIL] missing runbook: $RUNBOOK" >&2
  exit 1
fi

runbook_required_lines=(
  '`replay_env_*` 才是脚本写入的**确定性复放基线**'
  '做 RC 复放、审计引用或文档摘录时，应优先引用 `replay_env_*` 与 `replay_command=`'
  '复放输出根目录：`replay_out_dir=<abs-path>`（应为固定、可审计的绝对路径；`replay_command=` 中的 `OUT_DIR` 应与之对应）'
  '实际覆盖环境：`env_trnm_challenge_reexec_entry=<value|<unset>>`'
  '复放环境：`replay_env_trnm_challenge_reexec_entry=<resolved-entry-absolute-path>`'
  '解析后的入口：`challenge_reexec_entry=<resolved-entry-absolute-path>`'
)

for line in "${runbook_required_lines[@]}"; do
  if ! grep -Fq "$line" "$RUNBOOK"; then
    echo "[FAIL] missing runbook replay/env guard phrase: $line" >&2
    exit 1
  fi
done

if ! grep -q 'truth_source=$REPO_ROOT/RELEASE_READINESS.md' "$TARGET"; then
  echo "[FAIL] expected summary truth_source to stay pinned to RELEASE_READINESS.md" >&2
  exit 1
fi

if ! grep -q 'historical_evidence_only=true' "$TARGET"; then
  echo "[FAIL] expected summary to keep historical evidence boundary flag" >&2
  exit 1
fi

if ! grep -q 'evidence_scope=local_rc_rehearsal_not_current_release_ready_claim' "$TARGET"; then
  echo "[FAIL] expected summary to keep local RC evidence scope boundary" >&2
  exit 1
fi

if ! grep -Fq "TRNM_CHALLENGE_REEXEC_ENTRY='\${replay_challenge_entry}'" "$TARGET"; then
  echo "[FAIL] expected replay_command to pin deterministic challenge reexec entry" >&2
  exit 1
fi

if ! grep -q '^resolve_existing_path() {' "$TARGET"; then
  echo "[FAIL] expected helper to normalize resolved challenge entry paths" >&2
  exit 1
fi

if ! grep -Fq "printf '%s/%s\\n' \"\$dir\" \"\$base\"" "$TARGET"; then
  echo "[FAIL] expected resolved challenge entry helper to emit an absolute path" >&2
  exit 1
fi

if ! grep -Fq 'resolve_existing_path "$TRNM_CHALLENGE_REEXEC_ENTRY"' "$TARGET"; then
  echo "[FAIL] expected explicit challenge reexec override env to be normalized through the helper" >&2
  exit 1
fi

if ! grep -Fq 'if resolve_existing_path "$f"; then' "$TARGET"; then
  echo "[FAIL] expected discovered challenge reexec candidates to be normalized through the helper" >&2
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
