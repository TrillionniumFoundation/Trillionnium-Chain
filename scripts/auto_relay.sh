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
ROUNDS="${ROUNDS:-1}"
STEPS_FILE="${STEPS_FILE:-$ROOT/scripts/auto_relay.steps}"

mkdir -p "$OUT_DIR"

if [[ -f "$LOCK_FILE" ]]; then
  echo "[relay] lock exists: $LOCK_FILE" | tee -a "$LOG"
  echo "[relay] another run may be in progress; remove lock to force restart" | tee -a "$LOG"
  exit 11
fi
trap 'rm -f "$LOCK_FILE"' EXIT
printf "%s\n" "$RUN_ID" > "$LOCK_FILE"

# Default full pipeline (edit scripts/auto_relay.steps to override)
if [[ ! -f "$STEPS_FILE" ]]; then
  cat > "$STEPS_FILE" <<'EOF'
# one command per line; empty/# lines ignored
bash ./scripts/challenge_reexec_template_smoke.sh
bash ./scripts/worker_onchain_contract_smoke.sh
bash ./scripts/demo_storyline.sh
EOF
fi

STEPS=()
while IFS= read -r line; do
  [[ -z "${line// }" ]] && continue
  [[ "$line" =~ ^[[:space:]]*# ]] && continue
  STEPS+=("$line")
done < "$STEPS_FILE"

if [[ "${#STEPS[@]}" -eq 0 ]]; then
  echo "[relay] no steps loaded from $STEPS_FILE" | tee -a "$LOG"
  exit 12
fi

total_ok=0
total_fail=0

run_step() {
  local round="$1"
  local idx="$2"
  local cmd="$3"
  echo "[relay] [round $round/$ROUNDS] [step $idx/${#STEPS[@]}] $cmd" | tee -a "$LOG"

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[relay] DRY_RUN=1 skip execute" | tee -a "$LOG"
    printf -- '- [DRY-RUN] r%s-s%s: "%s"\n' "$round" "$idx" "$cmd" >> "$SUMMARY"
    return 0
  fi

  local step_log="$OUT_DIR/round-${round}-step-${idx}.log"
  if bash -lc "$cmd" >"$step_log" 2>&1; then
    echo "[relay] [OK] round=$round step=$idx" | tee -a "$LOG"
    printf -- '- [OK] r%s-s%s: "%s"\n' "$round" "$idx" "$cmd" >> "$SUMMARY"
    printf -- '  - log: "%s"\n' "$step_log" >> "$SUMMARY"
    total_ok=$((total_ok+1))
    return 0
  else
    rc=$?
    echo "[relay] [FAIL] round=$round step=$idx rc=$rc" | tee -a "$LOG"
    printf -- '- [FAIL] r%s-s%s: "%s" (rc=%s)\n' "$round" "$idx" "$cmd" "$rc" >> "$SUMMARY"
    printf -- '  - log: "%s"\n' "$step_log" >> "$SUMMARY"
    total_fail=$((total_fail+1))
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
  echo "- steps_file: \`$STEPS_FILE\`"
  echo "- rounds: \`$ROUNDS\`"
  echo "- dry_run: \`$DRY_RUN\`"
  echo "- stop_on_error: \`$STOP_ON_ERROR\`"
  echo
  echo "## Steps"
} > "$SUMMARY"

echo "[relay] start run_id=$RUN_ID out_dir=$OUT_DIR" | tee -a "$LOG"

for ((r=1; r<=ROUNDS; r++)); do
  round_ok_before=$total_ok
  round_fail_before=$total_fail

  for i in "${!STEPS[@]}"; do
    idx=$((i+1))
    run_step "$r" "$idx" "${STEPS[$i]}"
  done

  round_ok=$((total_ok-round_ok_before))
  round_fail=$((total_fail-round_fail_before))
  echo "[relay] [round-end] round=$r ok=$round_ok fail=$round_fail" | tee -a "$LOG"
  {
    echo
    echo "### Round $r result"
    echo "- ok: $round_ok"
    echo "- fail: $round_fail"
    echo "- ended_at: \`$(date '+%F %T')\`"
  } >> "$SUMMARY"
done

{
  echo
  echo "## Final Result"
  echo "- ok: $total_ok"
  echo "- fail: $total_fail"
  echo "- finished_at: \`$(date '+%F %T')\`"
} >> "$SUMMARY"

echo "[relay] done ok=$total_ok fail=$total_fail" | tee -a "$LOG"
echo "$SUMMARY"
