#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TS="$(date +%Y%m%d-%H%M%S)"
RUN_ID="relay-$TS-$$"
OUT_DIR="${OUT_DIR:-$ROOT/data/auto-relay/$RUN_ID}"
LOG="$OUT_DIR/run.log"
SUMMARY="$OUT_DIR/summary.md"
LOCK_FILE="${LOCK_FILE:-$ROOT/.auto-relay.lock}"
DRY_RUN="${DRY_RUN:-0}"
STOP_ON_ERROR="${STOP_ON_ERROR:-0}"

mkdir -p "$OUT_DIR"

if [[ -f "$LOCK_FILE" ]]; then
  echo "[relay] lock exists: $LOCK_FILE" | tee -a "$LOG"
  echo "[relay] another run may be in progress; remove lock to force restart" | tee -a "$LOG"
  exit 11
fi
trap 'rm -f "$LOCK_FILE"' EXIT
printf "%s\n" "$RUN_ID" > "$LOCK_FILE"

# Ordered steps (edit this list as backlog evolves)
STEPS=(
  "bash ./scripts/challenge_reexec_template_smoke.sh"
  "bash ./scripts/worker_onchain_contract_smoke.sh"
  "bash ./scripts/demo_storyline.sh"
)

status_ok=0
status_fail=0

run_step() {
  local idx="$1"
  local cmd="$2"
  echo "[relay] [step $idx/${#STEPS[@]}] $cmd" | tee -a "$LOG"

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[relay] DRY_RUN=1 skip execute" | tee -a "$LOG"
    printf -- '- [DRY-RUN] step %s: "%s"\n' "$idx" "$cmd" >> "$SUMMARY"
    return 0
  fi

  local step_log="$OUT_DIR/step-${idx}.log"
  if bash -lc "$cmd" >"$step_log" 2>&1; then
    echo "[relay] [OK] step $idx" | tee -a "$LOG"
    printf -- '- [OK] step %s: "%s"\n' "$idx" "$cmd" >> "$SUMMARY"
    printf -- '  - log: "%s"\n' "$step_log" >> "$SUMMARY"
    status_ok=$((status_ok+1))
    return 0
  else
    rc=$?
    echo "[relay] [FAIL] step $idx rc=$rc" | tee -a "$LOG"
    printf -- '- [FAIL] step %s: "%s" (rc=%s)\n' "$idx" "$cmd" "$rc" >> "$SUMMARY"
    printf -- '  - log: "%s"\n' "$step_log" >> "$SUMMARY"
    status_fail=$((status_fail+1))
    if [[ "$STOP_ON_ERROR" == "1" ]]; then
      return "$rc"
    fi
    return 0
  fi
}

{
  echo "# Auto Relay Summary"
  echo
  echo "- run_id: \`$RUN_ID\`"
  echo "- started_at: \`$(date '+%F %T')\`"
  echo "- root: \`$ROOT\`"
  echo "- dry_run: \`$DRY_RUN\`"
  echo "- stop_on_error: \`$STOP_ON_ERROR\`"
  echo
  echo "## Steps"
} > "$SUMMARY"

echo "[relay] start run_id=$RUN_ID out_dir=$OUT_DIR" | tee -a "$LOG"

for i in "${!STEPS[@]}"; do
  idx=$((i+1))
  run_step "$idx" "${STEPS[$i]}"
done

{
  echo
  echo "## Result"
  echo "- ok: $status_ok"
  echo "- fail: $status_fail"
  echo "- finished_at: \`$(date '+%F %T')\`"
} >> "$SUMMARY"

echo "[relay] done ok=$status_ok fail=$status_fail" | tee -a "$LOG"
echo "$SUMMARY"
