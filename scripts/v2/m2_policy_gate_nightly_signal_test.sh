#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT/trillionnium-rust"

TAG="m2-nightly-signal-test-$$-$(date +%s)"
AUDIT="run/audit/state-root-audit-${TAG}.txt"
BENCH="run/bench/bench-matrix-${TAG}.txt"
MIXED="run/bench/bench-mixed-matrix-${TAG}.txt"
P1_DIR="run/p1-integration-gate/${TAG}"
M2_LOG="$P1_DIR/m2_policy_gate.log"

mkdir -p "$(dirname "$AUDIT")" "$(dirname "$BENCH")" "$(dirname "$MIXED")" "$P1_DIR"

cleanup() {
  rm -f "$AUDIT" "$BENCH" "$MIXED"
  rm -f "run/health/nightly-summary-${TAG}-fail.md" "run/health/nightly-summary-${TAG}-pass.md" "run/health/nightly-summary-${TAG}-missing.md"
  rm -rf "$P1_DIR"
}
trap cleanup EXIT

echo 'summary ok=true mismatch=0 missing=0' >"$AUDIT"
echo 'elapsed_ms=10' >"$BENCH"
echo 'elapsed_ms=10' >"$MIXED"

# Case 1: M2 log present but missing default-drift guard assertion => must emit failure signal.
cat >"$M2_LOG" <<'EOF'
running 1 test
test market_effective_score_rewards_higher_reputation ... ok

test result: ok. 1 passed; 0 failed
EOF

OUT_FAIL="$(./scripts/nightly_attribution.sh | sed -n 's/^\[OK\] nightly attribution: //p' | tail -n1)"
[[ -f "$OUT_FAIL" ]] || { echo "[FAIL] missing attribution output for fail case"; exit 1; }

grep -q '^m2.policy_gate.assert_default_drift_guard=fail$' "$OUT_FAIL" || {
  echo "[FAIL] expected m2 default-drift guard to be fail"; cat "$OUT_FAIL"; exit 1;
}
grep -q '^attribution.labels=.*semantic-regression' "$OUT_FAIL" || {
  echo "[FAIL] expected semantic-regression label when m2 default-drift guard fails"; cat "$OUT_FAIL"; exit 1;
}
grep -q 'm2_policy_gate_default_drift_guard_fail' "$OUT_FAIL" || {
  echo "[FAIL] expected m2 default-drift failure reason"; cat "$OUT_FAIL"; exit 1;
}

SUMMARY_FAIL="run/health/nightly-summary-${TAG}-fail.md"
NIGHTLY_ATTRIBUTION_FILE="$OUT_FAIL" NIGHTLY_SUMMARY_OUT="$SUMMARY_FAIL" \
  python3 ./scripts/render_nightly_summary.py >/dev/null

grep -q 'default-drift guard assertion: `fail`' "$SUMMARY_FAIL" || {
  echo "[FAIL] expected summary to include m2 fail assertion status"; cat "$SUMMARY_FAIL"; exit 1;
}
grep -q 'failure_signal: `m2_policy_gate_default_drift_guard_not_pass`' "$SUMMARY_FAIL" || {
  echo "[FAIL] expected summary failure_signal for m2 default-drift guard"; cat "$SUMMARY_FAIL"; exit 1;
}

# Case 2: assertion exists and passes => must clear m2 failure reason.
cat >"$M2_LOG" <<'EOF'
running 1 test
test market_m2_policy_gate_guards_default_drift_to_min_boundaries ... ok

test result: ok. 1 passed; 0 failed
EOF

OUT_PASS="$(./scripts/nightly_attribution.sh | sed -n 's/^\[OK\] nightly attribution: //p' | tail -n1)"
[[ -f "$OUT_PASS" ]] || { echo "[FAIL] missing attribution output for pass case"; exit 1; }

grep -q '^m2.policy_gate.assert_default_drift_guard=pass$' "$OUT_PASS" || {
  echo "[FAIL] expected m2 default-drift guard to be pass"; cat "$OUT_PASS"; exit 1;
}
if grep -q 'm2_policy_gate_default_drift_guard_' "$OUT_PASS"; then
  echo "[FAIL] unexpected m2 default-drift failure reason in pass case"
  cat "$OUT_PASS"
  exit 1
fi

SUMMARY_PASS="run/health/nightly-summary-${TAG}-pass.md"
NIGHTLY_ATTRIBUTION_FILE="$OUT_PASS" NIGHTLY_SUMMARY_OUT="$SUMMARY_PASS" \
  python3 ./scripts/render_nightly_summary.py >/dev/null

grep -q 'default-drift guard assertion: `pass`' "$SUMMARY_PASS" || {
  echo "[FAIL] expected summary to include m2 pass assertion status"; cat "$SUMMARY_PASS"; exit 1;
}
if grep -q 'm2_policy_gate_default_drift_guard_not_pass' "$SUMMARY_PASS"; then
  echo "[FAIL] unexpected summary failure_signal in pass case"
  cat "$SUMMARY_PASS"
  exit 1
fi

# Case 3: M2 gate log missing => must mark assertion as missing and keep failure signal.
rm -f "$M2_LOG"
OUT_MISSING="$(./scripts/nightly_attribution.sh | sed -n 's/^\[OK\] nightly attribution: //p' | tail -n1)"
[[ -f "$OUT_MISSING" ]] || { echo "[FAIL] missing attribution output for missing-log case"; exit 1; }

grep -q '^m2.policy_gate.assert_default_drift_guard=missing$' "$OUT_MISSING" || {
  echo "[FAIL] expected m2 default-drift guard to be missing"; cat "$OUT_MISSING"; exit 1;
}
grep -q 'm2_policy_gate_default_drift_guard_missing' "$OUT_MISSING" || {
  echo "[FAIL] expected missing-log m2 default-drift failure reason"; cat "$OUT_MISSING"; exit 1;
}

SUMMARY_MISSING="run/health/nightly-summary-${TAG}-missing.md"
NIGHTLY_ATTRIBUTION_FILE="$OUT_MISSING" NIGHTLY_SUMMARY_OUT="$SUMMARY_MISSING" \
  python3 ./scripts/render_nightly_summary.py >/dev/null

grep -q 'default-drift guard assertion: `missing`' "$SUMMARY_MISSING" || {
  echo "[FAIL] expected summary to include m2 missing assertion status"; cat "$SUMMARY_MISSING"; exit 1;
}
grep -q 'failure_signal: `m2_policy_gate_default_drift_guard_not_pass`' "$SUMMARY_MISSING" || {
  echo "[FAIL] expected summary failure_signal for m2 missing assertion"; cat "$SUMMARY_MISSING"; exit 1;
}

echo "[PASS] nightly attribution + summary expose M2 policy gate default-drift guard signal"
