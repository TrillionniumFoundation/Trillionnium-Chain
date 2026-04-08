#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROFILE="${THRESHOLD_PROFILE:-stage2}"
case "$PROFILE" in
  stage1)
    CLASSIC_HARD_DEFAULT=600
    MIXED_HARD_DEFAULT=600
    ;;
  stage2)
    CLASSIC_HARD_DEFAULT=480
    MIXED_HARD_DEFAULT=560
    ;;
  *)
    CLASSIC_HARD_DEFAULT=480
    MIXED_HARD_DEFAULT=560
    ;;
esac

CLASSIC_HARD_MS="${BENCH_MAX_MS:-$CLASSIC_HARD_DEFAULT}"
MIXED_HARD_MS="${BENCH_MIXED_MAX_MS:-$MIXED_HARD_DEFAULT}"

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="run/health"
OUT="${NIGHTLY_ATTRIBUTION_OUT:-$OUT_DIR/nightly-attribution-$TS.txt}"
OUT_DIR="$(dirname "$OUT")"
mkdir -p "$OUT_DIR"

latest_audit="$(ls -1dt run/audit/state-root-audit-*.txt 2>/dev/null | head -n 1 || true)"
latest_bench="$(ls -1dt run/bench/bench-matrix-*.txt 2>/dev/null | head -n 1 || true)"
latest_mixed="$(ls -1dt run/bench/bench-mixed-matrix-*.txt 2>/dev/null | head -n 1 || true)"
latest_strategy_exp="$(ls -1dt run/bench/executor-strategy-exp-*.txt 2>/dev/null | head -n 1 || true)"
latest_hotspot_exp="$(ls -1dt run/bench/executor-hotspot-exp-*.txt 2>/dev/null | head -n 1 || true)"
latest_suggest="$(ls -1dt run/health/auto-adaptive-threshold-suggestion-*.txt 2>/dev/null | head -n 1 || true)"
latest_p1_gate="$(ls -1dt run/p1-integration-gate/* 2>/dev/null | head -n 1 || true)"
m2_policy_gate_log=""
m2_policy_gate_assert_default_drift_guard="missing"
if [[ -n "$latest_p1_gate" ]] && [[ -f "$latest_p1_gate/m2_policy_gate.log" ]]; then
  m2_policy_gate_log="$latest_p1_gate/m2_policy_gate.log"
  if python3 - "$m2_policy_gate_log" <<'PY' | grep -Eq '^[[:space:]]*test ([[:alnum:]_]+::)*market_m2_policy_gate_guards_default_drift_to_(min|max)_boundaries[[:space:]]+\.\.\.[[:space:]]+[Oo][Kk]([[:space:]].*)?\r?$'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding='utf-8', errors='ignore')
text = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', text)
text = text.translate({
    0xFEFF: None,
    0x200B: None,
    0x200C: None,
    0x200D: None,
    0x2060: None,
})
sys.stdout.write(text)
PY
  then
    m2_policy_gate_assert_default_drift_guard="pass"
  else
    m2_policy_gate_assert_default_drift_guard="fail"
  fi
fi

label_semantic=0
label_perf=0
label_env=0

reasons=()

if [[ -z "$latest_audit" ]] || [[ -z "$latest_bench" ]] || [[ -z "$latest_mixed" ]]; then
  label_env=1
  reasons+=("missing_expected_artifacts")
fi

if [[ -n "$latest_audit" ]]; then
  if ! grep -q 'summary ok=true mismatch=0 missing=0' "$latest_audit"; then
    label_semantic=1
    reasons+=("state_root_audit_failed")
  fi
fi

if [[ -f run/parallel-sanity.log ]]; then
  if grep -E '\[tx\] apply_error|rollback=true' run/parallel-sanity.log >/dev/null; then
    label_semantic=1
    reasons+=("parallel_apply_error_or_rollback")
  fi
fi

if [[ -f run/event-replay-smoke.log ]]; then
  if ! grep -q 'event_type=resolve' run/event-replay-smoke.log; then
    label_semantic=1
    reasons+=("event_replay_order_failed")
  fi
fi

if [[ "$m2_policy_gate_assert_default_drift_guard" != "pass" ]]; then
  label_semantic=1
  reasons+=("m2_policy_gate_default_drift_guard_${m2_policy_gate_assert_default_drift_guard}")
fi

max_elapsed() {
  local file="$1"
  awk -F= '/^elapsed_ms=/{if ($2+0>m) m=$2+0} END{if (m=="") m=0; print m}' "$file"
}

extract_auto_reason() {
  local file="$1"
  if [[ -z "$file" || ! -f "$file" ]]; then
    echo "none"
    return 0
  fi

  awk '
    /--- strategy=auto-adaptive ---/ {in_auto=1; next}
    /^--- strategy=/ {if (in_auto) exit; in_auto=0}
    in_auto && /^profile.auto.reason=/ {sub(/^profile.auto.reason=/, "", $0); print; found=1; exit}
    END {if (!found) print "unknown"}
  ' "$file"
}

extract_auto_use_hot_bucket() {
  local file="$1"
  if [[ -z "$file" || ! -f "$file" ]]; then
    echo "none"
    return 0
  fi

  awk '
    /--- strategy=auto-adaptive ---/ {in_auto=1; next}
    /^--- strategy=/ {if (in_auto) exit; in_auto=0}
    in_auto && /^profile.auto.use_hot_bucket=/ {sub(/^profile.auto.use_hot_bucket=/, "", $0); print; found=1; exit}
    END {if (!found) print "unknown"}
  ' "$file"
}

extract_elapsed_for_strategy() {
  local file="$1"
  local strategy="$2"
  if [[ -z "$file" || ! -f "$file" ]]; then
    echo ""
    return 0
  fi

  awk -v s="$strategy" '
    $0 ~ "--- strategy=" s " ---" {in_s=1; next}
    /^--- strategy=/ {if (in_s) exit; in_s=0}
    in_s && /^elapsed_ms=/ {sub(/^elapsed_ms=/, "", $0); print; found=1; exit}
    END {if (!found) print ""}
  ' "$file"
}

if [[ -n "$latest_bench" ]]; then
  classic_max="$(max_elapsed "$latest_bench")"
  if [[ "$classic_max" -gt "$CLASSIC_HARD_MS" ]]; then
    label_perf=1
    reasons+=("classic_elapsed_gt_hard(${classic_max}>${CLASSIC_HARD_MS})")
  fi
fi

if [[ -n "$latest_mixed" ]]; then
  mixed_max="$(max_elapsed "$latest_mixed")"
  if [[ "$mixed_max" -gt "$MIXED_HARD_MS" ]]; then
    label_perf=1
    reasons+=("mixed_elapsed_gt_hard(${mixed_max}>${MIXED_HARD_MS})")
  fi
fi

auto_reason_mixed="$(extract_auto_reason "$latest_strategy_exp")"
auto_used_mixed="$(extract_auto_use_hot_bucket "$latest_strategy_exp")"
auto_reason_hotspot="$(extract_auto_reason "$latest_hotspot_exp")"
auto_used_hotspot="$(extract_auto_use_hot_bucket "$latest_hotspot_exp")"

strategy_mismatch=0
tuning_recommended=0
orig_elapsed_mixed="$(extract_elapsed_for_strategy "$latest_strategy_exp" "original")"
auto_elapsed_mixed="$(extract_elapsed_for_strategy "$latest_strategy_exp" "auto-adaptive")"
orig_elapsed_hotspot="$(extract_elapsed_for_strategy "$latest_hotspot_exp" "original")"
auto_elapsed_hotspot="$(extract_elapsed_for_strategy "$latest_hotspot_exp" "auto-adaptive")"

if [[ -n "$latest_suggest" ]] && grep -q '^suggest.recommended=true' "$latest_suggest"; then
  tuning_recommended=1
  reasons+=("auto_threshold_tuning_recommended")
fi

if [[ "$auto_used_mixed" == "true" && -n "$orig_elapsed_mixed" && -n "$auto_elapsed_mixed" ]]; then
  if [[ "$auto_elapsed_mixed" -gt "$orig_elapsed_mixed" ]]; then
    strategy_mismatch=1
    reasons+=("auto_strategy_mismatch_mixed(${auto_elapsed_mixed}>${orig_elapsed_mixed})")
  fi
fi

if [[ "$auto_used_hotspot" == "true" && -n "$orig_elapsed_hotspot" && -n "$auto_elapsed_hotspot" ]]; then
  if [[ "$auto_elapsed_hotspot" -gt "$orig_elapsed_hotspot" ]]; then
    strategy_mismatch=1
    reasons+=("auto_strategy_mismatch_hotspot(${auto_elapsed_hotspot}>${orig_elapsed_hotspot})")
  fi
fi

labels=()
[[ $label_semantic -eq 1 ]] && labels+=("semantic-regression")
[[ $label_perf -eq 1 ]] && labels+=("performance-regression")
[[ $label_env -eq 1 ]] && labels+=("environment-flaky")
[[ $strategy_mismatch -eq 1 ]] && labels+=("strategy-mismatch")
[[ $tuning_recommended -eq 1 ]] && labels+=("tuning-recommended")
if [[ ${#labels[@]} -eq 0 ]]; then
  labels+=("healthy")
fi

{
  echo "attribution.profile=$PROFILE"
  echo "attribution.labels=$(IFS=,; echo "${labels[*]}")"
  echo "attribution.reasons=$(IFS=';'; echo "${reasons[*]:-none}")"
  echo "audit.file=${latest_audit:-none}"
  echo "bench.file=${latest_bench:-none}"
  echo "mixed.file=${latest_mixed:-none}"
  echo "strategy_exp.file=${latest_strategy_exp:-none}"
  echo "hotspot_exp.file=${latest_hotspot_exp:-none}"
  echo "threshold_suggest.file=${latest_suggest:-none}"
  echo "p1_gate.latest_dir=${latest_p1_gate:-none}"
  echo "m2.policy_gate.log=${m2_policy_gate_log:-none}"
  echo "m2.policy_gate.assert_default_drift_guard=${m2_policy_gate_assert_default_drift_guard}"
  echo "strategy_exp.auto.use_hot_bucket=${auto_used_mixed}"
  echo "strategy_exp.auto.reason=${auto_reason_mixed}"
  echo "strategy_exp.elapsed.original_ms=${orig_elapsed_mixed:-none}"
  echo "strategy_exp.elapsed.auto_ms=${auto_elapsed_mixed:-none}"
  echo "hotspot_exp.auto.use_hot_bucket=${auto_used_hotspot}"
  echo "hotspot_exp.auto.reason=${auto_reason_hotspot}"
  echo "hotspot_exp.elapsed.original_ms=${orig_elapsed_hotspot:-none}"
  echo "hotspot_exp.elapsed.auto_ms=${auto_elapsed_hotspot:-none}"
  echo "threshold.classic.hard_ms=$CLASSIC_HARD_MS"
  echo "threshold.mixed.hard_ms=$MIXED_HARD_MS"
} | tee "$OUT"

echo "::notice title=nightly-attribution::labels=$(IFS=,; echo "${labels[*]}") auto_mixed=${auto_reason_mixed} auto_hotspot=${auto_reason_hotspot}"
if [[ $strategy_mismatch -eq 1 ]]; then
  echo "::warning title=nightly-strategy-mismatch::auto-adaptive slower than original on latest experiment"
fi
if [[ $tuning_recommended -eq 1 ]]; then
  echo "::notice title=nightly-tuning-recommended::auto-adaptive thresholds differ from current recommended baseline"
fi
echo "[OK] nightly attribution: $OUT"
