#!/usr/bin/env bash
set -euo pipefail

# Keep parsing/output deterministic across heterogeneous CI runners.
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
export LC_NUMERIC=C
export TZ=UTC

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT/trillionnium"

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

# Case 1.5: avoid false pass when failure details contain target test name + trailing "ok" text.
cat >"$M2_LOG" <<'EOF'
running 1 test
test market_m2_policy_gate_guards_default_drift_to_min_boundaries ... FAILED

failures:
market_m2_policy_gate_guards_default_drift_to_min_boundaries panic detail says not ok
test result: FAILED. 0 passed; 1 failed
EOF

OUT_FALSE_PASS_GUARD="$(./scripts/nightly_attribution.sh | sed -n 's/^\[OK\] nightly attribution: //p' | tail -n1)"
[[ -f "$OUT_FALSE_PASS_GUARD" ]] || { echo "[FAIL] missing attribution output for false-pass-guard case"; exit 1; }

grep -q '^m2.policy_gate.assert_default_drift_guard=fail$' "$OUT_FALSE_PASS_GUARD" || {
  echo "[FAIL] expected m2 default-drift guard to stay fail on failure log with misleading ok text"; cat "$OUT_FALSE_PASS_GUARD"; exit 1;
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

# Case 2.5: tolerate indented/timed cargo output for the same passing assertion.
cat >"$M2_LOG" <<'EOF'
running 1 test
    test market_m2_policy_gate_guards_default_drift_to_min_boundaries ... ok (12 ms)

test result: ok. 1 passed; 0 failed
EOF

OUT_PASS_FORMAT_VARIANT="$(./scripts/nightly_attribution.sh | sed -n 's/^\[OK\] nightly attribution: //p' | tail -n1)"
[[ -f "$OUT_PASS_FORMAT_VARIANT" ]] || { echo "[FAIL] missing attribution output for pass format-variant case"; exit 1; }

grep -q '^m2.policy_gate.assert_default_drift_guard=pass$' "$OUT_PASS_FORMAT_VARIANT" || {
  echo "[FAIL] expected m2 default-drift guard to pass for indented/timed output"; cat "$OUT_PASS_FORMAT_VARIANT"; exit 1;
}
if grep -q 'm2_policy_gate_default_drift_guard_' "$OUT_PASS_FORMAT_VARIANT"; then
  echo "[FAIL] unexpected m2 default-drift failure reason in pass format-variant case"
  cat "$OUT_PASS_FORMAT_VARIANT"
  exit 1
fi

# Case 2.6: tolerate namespaced test names emitted by some cargo harness formats.
cat >"$M2_LOG" <<'EOF'
running 1 test
test market::policy::market_m2_policy_gate_guards_default_drift_to_min_boundaries ... ok

test result: ok. 1 passed; 0 failed
EOF

OUT_PASS_NAMESPACED="$(./scripts/nightly_attribution.sh | sed -n 's/^\[OK\] nightly attribution: //p' | tail -n1)"
[[ -f "$OUT_PASS_NAMESPACED" ]] || { echo "[FAIL] missing attribution output for namespaced pass case"; exit 1; }

grep -q '^m2.policy_gate.assert_default_drift_guard=pass$' "$OUT_PASS_NAMESPACED" || {
  echo "[FAIL] expected m2 default-drift guard to pass for namespaced output"; cat "$OUT_PASS_NAMESPACED"; exit 1;
}
if grep -q 'm2_policy_gate_default_drift_guard_' "$OUT_PASS_NAMESPACED"; then
  echo "[FAIL] unexpected m2 default-drift failure reason in namespaced pass case"
  cat "$OUT_PASS_NAMESPACED"
  exit 1
fi

# Case 2.7: accept max-boundary drift guard variant as equivalent passing evidence.
cat >"$M2_LOG" <<'EOF'
running 1 test
test market::policy::market_m2_policy_gate_guards_default_drift_to_max_boundaries ... ok

test result: ok. 1 passed; 0 failed
EOF

OUT_PASS_MAX_BOUNDARY="$(./scripts/nightly_attribution.sh | sed -n 's/^\[OK\] nightly attribution: //p' | tail -n1)"
[[ -f "$OUT_PASS_MAX_BOUNDARY" ]] || { echo "[FAIL] missing attribution output for max-boundary pass case"; exit 1; }

grep -q '^m2.policy_gate.assert_default_drift_guard=pass$' "$OUT_PASS_MAX_BOUNDARY" || {
  echo "[FAIL] expected m2 default-drift guard to pass for max-boundary output"; cat "$OUT_PASS_MAX_BOUNDARY"; exit 1;
}
if grep -q 'm2_policy_gate_default_drift_guard_' "$OUT_PASS_MAX_BOUNDARY"; then
  echo "[FAIL] unexpected m2 default-drift failure reason in max-boundary pass case"
  cat "$OUT_PASS_MAX_BOUNDARY"
  exit 1
fi

# Case 2.8: tolerate CRLF line endings from cross-platform wrappers.
python3 - <<'PY' "$M2_LOG"
from pathlib import Path
import sys

log = Path(sys.argv[1])
log.write_bytes(
    b"running 1 test\r\n"
    b"test market_m2_policy_gate_guards_default_drift_to_min_boundaries ... ok\r\n"
    b"\r\n"
    b"test result: ok. 1 passed; 0 failed\r\n"
)
PY

OUT_PASS_CRLF="$(./scripts/nightly_attribution.sh | sed -n 's/^\[OK\] nightly attribution: //p' | tail -n1)"
[[ -f "$OUT_PASS_CRLF" ]] || { echo "[FAIL] missing attribution output for CRLF pass case"; exit 1; }

grep -q '^m2.policy_gate.assert_default_drift_guard=pass$' "$OUT_PASS_CRLF" || {
  echo "[FAIL] expected m2 default-drift guard to pass for CRLF output"; cat "$OUT_PASS_CRLF"; exit 1;
}
if grep -q 'm2_policy_gate_default_drift_guard_' "$OUT_PASS_CRLF"; then
  echo "[FAIL] unexpected m2 default-drift failure reason in CRLF pass case"
  cat "$OUT_PASS_CRLF"
  exit 1
fi

# Case 2.9: tolerate ANSI color escape codes from colored cargo output wrappers.
python3 - <<'PY' "$M2_LOG"
from pathlib import Path
import sys

log = Path(sys.argv[1])
log.write_bytes(
    b"running 1 test\n"
    b"\x1b[32mtest market::policy::market_m2_policy_gate_guards_default_drift_to_min_boundaries ... ok\x1b[0m\n"
    b"\n"
    b"test result: ok. 1 passed; 0 failed\n"
)
PY

OUT_PASS_ANSI="$(./scripts/nightly_attribution.sh | sed -n 's/^\[OK\] nightly attribution: //p' | tail -n1)"
[[ -f "$OUT_PASS_ANSI" ]] || { echo "[FAIL] missing attribution output for ANSI pass case"; exit 1; }

grep -q '^m2.policy_gate.assert_default_drift_guard=pass$' "$OUT_PASS_ANSI" || {
  echo "[FAIL] expected m2 default-drift guard to pass for ANSI-colored output"; cat "$OUT_PASS_ANSI"; exit 1;
}
if grep -q 'm2_policy_gate_default_drift_guard_' "$OUT_PASS_ANSI"; then
  echo "[FAIL] unexpected m2 default-drift failure reason in ANSI pass case"
  cat "$OUT_PASS_ANSI"
  exit 1
fi

# Case 2.10: tolerate BOM + zero-width Unicode noise from clipboard/log wrappers.
python3 - <<'PY' "$M2_LOG"
from pathlib import Path
import sys

log = Path(sys.argv[1])
log.write_text(
    "running 1 test\n"
    "\ufefftest market\u200d_m2_policy_gate_guards_default_drift_to_min_boundaries ... ok\u200b\n"
    "\n"
    "test result: ok. 1 passed; 0 failed\n",
    encoding='utf-8'
)
PY

OUT_PASS_UNICODE_NOISE="$(./scripts/nightly_attribution.sh | sed -n 's/^\[OK\] nightly attribution: //p' | tail -n1)"
[[ -f "$OUT_PASS_UNICODE_NOISE" ]] || { echo "[FAIL] missing attribution output for Unicode-noise pass case"; exit 1; }

grep -q '^m2.policy_gate.assert_default_drift_guard=pass$' "$OUT_PASS_UNICODE_NOISE" || {
  echo "[FAIL] expected m2 default-drift guard to pass for Unicode-noise output"; cat "$OUT_PASS_UNICODE_NOISE"; exit 1;
}
if grep -q 'm2_policy_gate_default_drift_guard_' "$OUT_PASS_UNICODE_NOISE"; then
  echo "[FAIL] unexpected m2 default-drift failure reason in Unicode-noise pass case"
  cat "$OUT_PASS_UNICODE_NOISE"
  exit 1
fi

# Case 2.11: tolerate uppercase OK token from wrapper-normalized harness output.
cat >"$M2_LOG" <<'EOF'
running 1 test
test market_m2_policy_gate_guards_default_drift_to_min_boundaries ... OK

test result: ok. 1 passed; 0 failed
EOF

OUT_PASS_UPPER_OK="$(./scripts/nightly_attribution.sh | sed -n 's/^\[OK\] nightly attribution: //p' | tail -n1)"
[[ -f "$OUT_PASS_UPPER_OK" ]] || { echo "[FAIL] missing attribution output for uppercase OK pass case"; exit 1; }

grep -q '^m2.policy_gate.assert_default_drift_guard=pass$' "$OUT_PASS_UPPER_OK" || {
  echo "[FAIL] expected m2 default-drift guard to pass for uppercase OK output"; cat "$OUT_PASS_UPPER_OK"; exit 1;
}
if grep -q 'm2_policy_gate_default_drift_guard_' "$OUT_PASS_UPPER_OK"; then
  echo "[FAIL] unexpected m2 default-drift failure reason in uppercase OK pass case"
  cat "$OUT_PASS_UPPER_OK"
  exit 1
fi

# Case 2.12: tolerate tab/multi-space delimiters around ellipsis and status token.
python3 - <<'PY' "$M2_LOG"
from pathlib import Path
import sys

log = Path(sys.argv[1])
log.write_text(
    "running 1 test\n"
    "test market_m2_policy_gate_guards_default_drift_to_min_boundaries\t...    ok\n"
    "\n"
    "test result: ok. 1 passed; 0 failed\n",
    encoding='utf-8'
)
PY

OUT_PASS_SPACING_VARIANT="$(./scripts/nightly_attribution.sh | sed -n 's/^\[OK\] nightly attribution: //p' | tail -n1)"
[[ -f "$OUT_PASS_SPACING_VARIANT" ]] || { echo "[FAIL] missing attribution output for spacing-variant pass case"; exit 1; }

grep -q '^m2.policy_gate.assert_default_drift_guard=pass$' "$OUT_PASS_SPACING_VARIANT" || {
  echo "[FAIL] expected m2 default-drift guard to pass for tab/multi-space output"; cat "$OUT_PASS_SPACING_VARIANT"; exit 1;
}
if grep -q 'm2_policy_gate_default_drift_guard_' "$OUT_PASS_SPACING_VARIANT"; then
  echo "[FAIL] unexpected m2 default-drift failure reason in spacing-variant pass case"
  cat "$OUT_PASS_SPACING_VARIANT"
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
