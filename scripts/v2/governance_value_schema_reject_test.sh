#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ROADMAP_PROGRESS_FILE="$ROOT/docs/development/roadmap-progress.json"
PAUSE_FILE="$ROOT/.auto-iterate.pause"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

if [[ -f "$ROADMAP_PROGRESS_FILE" ]]; then
  read -r progress_pct lane_b_paused_flag roadmap_updated_at roadmap_source <<<"$(python3 - "$ROADMAP_PROGRESS_FILE" <<'PY'
import json,sys
p=sys.argv[1]
try:
    obj=json.load(open(p,'r',encoding='utf-8'))
    v=int(obj.get('development_doc_roadmap_progress_pct', 0))
    paused=bool(obj.get('laneB_paused_until_100', False))
    updated_at=str(obj.get('updated_at', '')).strip()
    source=str(obj.get('source', '')).strip()
    print(v, 'true' if paused else 'false', updated_at or '-', source or '-')
except Exception:
    print(0, 'false', '-', '-')
PY
)"
else
  progress_pct=0
  lane_b_paused_flag=false
  roadmap_updated_at=-
  roadmap_source=-
fi

pause_signal="absent"
if [[ "$lane_b_paused_flag" == "true" ]]; then
  pause_signal="roadmap_flag"
elif [[ -f "$PAUSE_FILE" ]]; then
  pause_signal="pause_file"
fi

if [[ "$progress_pct" -lt 100 && "$lane_b_paused_flag" != "true" ]]; then
  echo "[FAIL] laneB governance: roadmap progress ${progress_pct}% < 100%, require laneB_paused_until_100=true in $ROADMAP_PROGRESS_FILE (pause file alone is insufficient)" >&2
  exit 1
fi

if [[ "$roadmap_updated_at" == "-" || "$roadmap_source" == "-" ]]; then
  echo "[FAIL] laneB governance: roadmap-progress metadata incomplete, require non-empty updated_at/source in $ROADMAP_PROGRESS_FILE" >&2
  exit 1
fi

echo "[GATE] laneB governance: roadmap progress=${progress_pct}% pause_signal=${pause_signal} updated_at=${roadmap_updated_at} source=${roadmap_source}"

cd "$ROOT/trillionnium"

echo "[TEST] governance_value_schema_reject: invalid value should be rejected"
cargo test -q -p trnm-state governance_param_schema_rejects_invalid_u64_values -- --nocapture
cargo test -q -p trnm-state emergency_pause_requires_strict_bool_literal -- --nocapture
cargo test -q -p trnm-state emergency_pause_checked_path_is_immediate_and_non_cancellable -- --nocapture
cargo test -q -p trnm-state emergency_pause_checked_noop_update_is_idempotent_after_pause -- --nocapture
cargo test -q -p trnm-state emergency_pause_checked_path_rejects_non_canonical_key_id -- --nocapture
cargo test -q -p trnm-state emergency_pause_checked_path_key_id_validation_precedes_bool_schema_validation -- --nocapture
cargo test -q -p trnm-state emergency_pause_checked_path_rejects_key_id_shadowing -- --nocapture
cargo test -q -p trnm-state emergency_pause_does_not_bypass_sensitive_timelock_guards -- --nocapture
cargo test -q -p trnm-rpc governance_state_merge_gate_keeps_emergency_pause_seeded_unpaused -- --nocapture
cargo test -q -p trnm-rpc governance_state_merge_gate_rejects_non_canonical_emergency_pause_key_id -- --nocapture
cargo test -q -p trnm-rpc governance_state_merge_gate_emergency_pause_rejects_whitespace_bool_without_side_effects -- --nocapture

echo "[OK] governance_value_schema_reject passed"
