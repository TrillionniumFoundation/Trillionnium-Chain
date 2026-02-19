#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/data/p0-acceptance}"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$OUT_DIR/$TS"
mkdir -p "$RUN_DIR"
SUMMARY_TXT="$RUN_DIR/summary.txt"
SUMMARY_JSON="$RUN_DIR/summary.json"

if [[ "${1:-}" == "--help" ]]; then
  cat <<EOF
Usage: ./scripts/p0_acceptance.sh [--quick] [--with-p1] [--with-reexec]

Runs a standardized P0 acceptance bundle and emits:
- summary.txt (human readable)
- summary.json (machine readable)
- step logs under data/p0-acceptance/<timestamp>/

Options:
  --quick       skip full alpha acceptance suite
  --with-p1     include P1 worker reconcile smoke step
  --with-reexec include challenge re-exec resolve-template smoke step
EOF
  exit 0
fi

QUICK=0
WITH_P1=0
WITH_REEXEC=0
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    --with-p1) WITH_P1=1 ;;
    --with-reexec) WITH_REEXEC=1 ;;
  esac
done

steps=(
  "check_pouw_commands|cd '$ROOT/chain' && ./tools/check_pouw_commands.sh"
  "smoke_pouw_cli_flow|cd '$ROOT/chain' && ./tools/smoke_pouw_cli_flow.sh"
)

if [[ "$QUICK" -eq 0 ]]; then
  steps+=("alpha_acceptance|cd '$ROOT' && ./scripts/run_alpha_acceptance.sh")
fi

if [[ "$WITH_P1" -eq 1 ]]; then
  steps+=("worker_reconcile_smoke|cd '$ROOT' && ./scripts/worker_reconcile_smoke.sh")
fi

if [[ "$WITH_REEXEC" -eq 1 ]]; then
  steps+=("challenge_reexec_template_smoke|cd '$ROOT' && ./scripts/challenge_reexec_resolve_template.sh 0 match")
fi

pass=0
fail=0

echo "Trillionnium P0 acceptance run @ $TS" | tee "$SUMMARY_TXT"
echo "output_dir=$RUN_DIR" | tee -a "$SUMMARY_TXT"

echo "{" > "$SUMMARY_JSON"
echo "  \"timestamp\": \"$TS\"," >> "$SUMMARY_JSON"
echo "  \"quick\": $QUICK," >> "$SUMMARY_JSON"
echo "  \"with_p1\": $WITH_P1," >> "$SUMMARY_JSON"
echo "  \"with_reexec\": $WITH_REEXEC," >> "$SUMMARY_JSON"
echo "  \"steps\": [" >> "$SUMMARY_JSON"

for i in "${!steps[@]}"; do
  IFS='|' read -r name cmd <<<"${steps[$i]}"
  log_file="$RUN_DIR/${name}.log"

  echo "" | tee -a "$SUMMARY_TXT"
  echo "===== $name =====" | tee -a "$SUMMARY_TXT"

  set +e
  bash -lc "$cmd" >"$log_file" 2>&1
  rc=$?
  set -e

  status="PASS"
  if [[ $rc -ne 0 ]]; then
    status="FAIL"
    fail=$((fail + 1))
  else
    pass=$((pass + 1))
  fi

  echo "$status: $name (rc=$rc, log=$log_file)" | tee -a "$SUMMARY_TXT"

  comma=","
  if [[ "$i" -eq "$((${#steps[@]} - 1))" ]]; then
    comma=""
  fi
  cat >> "$SUMMARY_JSON" <<EOF
    {"name":"$name","status":"$status","rc":$rc,"log":"$log_file"}$comma
EOF

done

total=$((pass + fail))
echo "  ]," >> "$SUMMARY_JSON"
echo "  \"total\": $total," >> "$SUMMARY_JSON"
echo "  \"pass\": $pass," >> "$SUMMARY_JSON"
echo "  \"fail\": $fail" >> "$SUMMARY_JSON"
echo "}" >> "$SUMMARY_JSON"

echo "" | tee -a "$SUMMARY_TXT"
echo "RESULT: total=$total pass=$pass fail=$fail" | tee -a "$SUMMARY_TXT"
echo "SUMMARY_TXT=$SUMMARY_TXT" | tee -a "$SUMMARY_TXT"
echo "SUMMARY_JSON=$SUMMARY_JSON" | tee -a "$SUMMARY_TXT"

if [[ $fail -gt 0 ]]; then
  exit 1
fi
