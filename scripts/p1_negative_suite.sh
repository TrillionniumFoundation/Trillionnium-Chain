#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/data/p1-negative}"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$OUT_DIR/$TS"
mkdir -p "$RUN_DIR"
SUMMARY_TXT="$RUN_DIR/summary.txt"
SUMMARY_JSON="$RUN_DIR/summary.json"

if [[ "${1:-}" == "--help" ]]; then
  cat <<EOF
Usage: ./scripts/p1_negative_suite.sh

Runs P1 negative/adversarial coverage suite with machine-readable outputs.
Current coverage:
- unauthorized authority calls (resolve/slash)
- timeout path
- challenge path
- restart/reconcile recovery path

Optional env:
- WITH_RUST_VERIFY=1   run rust sidecar verification after suite

Artifacts:
- data/p1-negative/<timestamp>/summary.txt
- data/p1-negative/<timestamp>/summary.json
- per-step logs
EOF
  exit 0
fi

BIN="${BIN:-$ROOT/build/chaind}"
HOME_DIR="${HOME_DIR:-/Users/qianqi/.chain}"
NODE="${NODE:-tcp://127.0.0.1:26657}"
WITH_RUST_VERIFY="${WITH_RUST_VERIFY:-0}"

ensure_chain_up() {
  if "$BIN" status --home "$HOME_DIR" --node "$NODE" >/dev/null 2>&1; then
    echo "[preflight] chain is up" | tee -a "$SUMMARY_TXT"
    return 0
  fi

  echo "[preflight] chain is down. Please start the project dev chain first (recommended: 'cd chain && ignite chain serve')." | tee -a "$SUMMARY_TXT"
  echo "[preflight] aborting to avoid false negatives from wrong local state/genesis." | tee -a "$SUMMARY_TXT"
  return 1
}

steps=(
  "unauthorized_authority_calls|cd '$ROOT' && ./scripts/scenario_D_slash.sh"
  "timeout_path|cd '$ROOT' && WAIT_SEC=8 ./scripts/scenario_B_timeout.sh"
  "challenge_path|cd '$ROOT' && ./scripts/scenario_C_challenge.sh"
  "restart_reconcile_recovery|cd '$ROOT' && ./scripts/worker_reconcile_smoke.sh"
  "forged_reveal_rejection|cd '$ROOT' && ./scripts/scenario_F_forged_reveal.sh"
  "duplicate_reveal_rejection|cd '$ROOT' && ./scripts/scenario_G_duplicate_reveal.sh"
)

pass=0
fail=0
skip=0

verifier_enabled=false
verifier_rc=0
verifier_export_dir=""
verifier_output_dir=""
verifier_matched=0
verifier_mismatch=0


echo "Trillionnium P1 negative suite @ $TS" | tee "$SUMMARY_TXT"
echo "output_dir=$RUN_DIR" | tee -a "$SUMMARY_TXT"

ensure_chain_up

echo "{" > "$SUMMARY_JSON"
echo "  \"timestamp\": \"$TS\"," >> "$SUMMARY_JSON"
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
  if [[ $rc -eq 10 ]]; then
    status="SKIP"
    skip=$((skip + 1))
  elif [[ $rc -ne 0 ]]; then
    status="FAIL"
    fail=$((fail + 1))
  else
    pass=$((pass + 1))
  fi

  echo "$status: $name (rc=$rc, log=$log_file)" | tee -a "$SUMMARY_TXT"

  comma=","
  if [[ "$i" -eq "$(( ${#steps[@]} - 1 ))" ]]; then
    comma=""
  fi
  cat >> "$SUMMARY_JSON" <<EOF
    {"name":"$name","status":"$status","rc":$rc,"log":"$log_file"}$comma
EOF

done

if [[ "$WITH_RUST_VERIFY" == "1" ]]; then
  verifier_enabled=true
  echo "" | tee -a "$SUMMARY_TXT"
  echo "===== rust_verifier_sidecar =====" | tee -a "$SUMMARY_TXT"

  set +e
  export_out="$(P1_DIR="$OUT_DIR" RUN_DIR="$RUN_DIR" "$ROOT/scripts/export_verifier_inputs.sh" 2>&1)"
  export_rc=$?
  set -e
  echo "$export_out" | tee "$RUN_DIR/rust-verifier-export.log" >/dev/null

  if [[ $export_rc -ne 0 ]]; then
    verifier_rc=1
    fail=$((fail + 1))
    echo "FAIL: verifier export failed (log=$RUN_DIR/rust-verifier-export.log)" | tee -a "$SUMMARY_TXT"
  else
    verifier_export_dir="$(echo "$export_out" | awk -F= '/^output_dir=/{print $2}')"
    verifier_output_dir="$ROOT/data/rust-verifier-local/$TS"

    set +e
    run_out="$(PATH="/opt/homebrew/opt/rustup/bin:$PATH" INPUT_DIR="$verifier_export_dir" OUT_DIR="$verifier_output_dir" "$ROOT/scripts/run_rust_verifier_poc.sh" 2>&1)"
    run_rc=$?
    set -e
    echo "$run_out" | tee "$RUN_DIR/rust-verifier-run.log" >/dev/null

    if [[ $run_rc -ne 0 ]]; then
      verifier_rc=1
      fail=$((fail + 1))
      echo "FAIL: verifier run failed (log=$RUN_DIR/rust-verifier-run.log)" | tee -a "$SUMMARY_TXT"
    else
      verifier_mismatch="$(python3 - <<PY
import json,glob
c=0
for f in glob.glob('$verifier_output_dir/*.json'):
    with open(f) as fh:
        o=json.load(fh)
    if not o.get('matched',False):
        c+=1
print(c)
PY
)"
      verifier_matched="$(python3 - <<PY
import json,glob
c=0
for f in glob.glob('$verifier_output_dir/*.json'):
    with open(f) as fh:
        o=json.load(fh)
    if o.get('matched',False):
        c+=1
print(c)
PY
)"

      if [[ "$verifier_mismatch" != "0" ]]; then
        verifier_rc=1
        fail=$((fail + 1))
        echo "FAIL: verifier mismatch detected (matched=$verifier_matched mismatch=$verifier_mismatch)" | tee -a "$SUMMARY_TXT"
      else
        echo "PASS: verifier matched all exported inputs (matched=$verifier_matched)" | tee -a "$SUMMARY_TXT"
      fi
    fi
  fi
fi

total=$((pass + fail + skip))
echo "  ]," >> "$SUMMARY_JSON"
echo "  \"total\": $total," >> "$SUMMARY_JSON"
echo "  \"pass\": $pass," >> "$SUMMARY_JSON"
echo "  \"fail\": $fail," >> "$SUMMARY_JSON"
echo "  \"skip\": $skip," >> "$SUMMARY_JSON"
echo "  \"with_rust_verify\": $verifier_enabled," >> "$SUMMARY_JSON"
echo "  \"rust_verify_rc\": $verifier_rc," >> "$SUMMARY_JSON"
echo "  \"rust_verify_export_dir\": \"$verifier_export_dir\"," >> "$SUMMARY_JSON"
echo "  \"rust_verify_output_dir\": \"$verifier_output_dir\"," >> "$SUMMARY_JSON"
echo "  \"rust_verify_matched\": $verifier_matched," >> "$SUMMARY_JSON"
echo "  \"rust_verify_mismatch\": $verifier_mismatch" >> "$SUMMARY_JSON"
echo "}" >> "$SUMMARY_JSON"

echo "" | tee -a "$SUMMARY_TXT"
echo "RESULT: total=$total pass=$pass fail=$fail skip=$skip" | tee -a "$SUMMARY_TXT"
if [[ "$verifier_enabled" == "true" ]]; then
  echo "RUST_VERIFY: rc=$verifier_rc matched=$verifier_matched mismatch=$verifier_mismatch" | tee -a "$SUMMARY_TXT"
  echo "RUST_VERIFY_EXPORT_DIR=$verifier_export_dir" | tee -a "$SUMMARY_TXT"
  echo "RUST_VERIFY_OUTPUT_DIR=$verifier_output_dir" | tee -a "$SUMMARY_TXT"
fi
echo "SUMMARY_TXT=$SUMMARY_TXT" | tee -a "$SUMMARY_TXT"
echo "SUMMARY_JSON=$SUMMARY_JSON" | tee -a "$SUMMARY_TXT"

if [[ $fail -gt 0 ]]; then
  exit 1
fi
