set -euo pipefail
python3 scripts/ci/w1_qrom_closure_current_controls.py run --roster-sha256 "$W1_CLOSURE_ROSTER_SHA256" --output "$W1_CLOSURE_OUT" 2>&1 | tee "$W1_CLOSURE_OUT/named-controls.log"
python3 scripts/ci/w1_qrom_closure_current_controls.py check --roster-sha256 "$W1_CLOSURE_ROSTER_SHA256" --output "$W1_CLOSURE_OUT" 2>&1 | tee "$W1_CLOSURE_OUT/named-controls-check.log"
