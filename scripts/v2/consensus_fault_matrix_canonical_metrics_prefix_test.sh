#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/trillionnium/scripts/run_consensus_fault_matrix.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-consensus-metrics-prefix.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/home" "$TMP/out"
cat >"$TMP/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "[block] node=fixture height=1 state_root=fixture-root"
case "${TRNM_FIXTURE_METRICS_STYLE:-canonical}" in
  stale)
    echo "[consensus] finality_p50_ms=1 finality_p95_ms=2 bft_committed_heights=1 bft_round_change_total=0 bft_round_change_backoff_total_ms=0"
    ;;
  decoy)
    echo "[consensus] finality_avg_ms=1 finality_p50_ms=1 decoy_finality_p95_ms=2 decoy_bft_committed_heights=1 decoy_bft_round_change_total=0 decoy_bft_round_change_backoff_total_ms=0"
    ;;
  *)
    echo "[consensus] finality_avg_ms=1 finality_p50_ms=1 finality_p95_ms=2 bft_committed_heights=1 bft_round_change_total=0 bft_round_change_backoff_total_ms=0"
    ;;
esac
EOF
chmod +x "$TMP/bin/cargo"

cat >"$TMP/home/.bash_profile" <<EOF
export PATH="$TMP/bin:/usr/bin:/bin"
EOF

HOME="$TMP/home" \
PATH="$TMP/bin:/usr/bin:/bin" \
OUT_DIR="$TMP/out" \
CONSENSUS_FAULT_MATRIX_OUT="$TMP/out/report.txt" \
CASE_FILTER=baseline \
EXPECTED_CASES=1 \
GATE_MODE=hard \
ALLOW_FAIL=0 \
"$GATE" >"$TMP/gate.log" 2>&1

grep -q '^result=PASS p95=2 round_change=0 committed=1 recovery_ms=0 ' "$TMP/out/report.txt"
grep -q '^status=PASS$' "$TMP/out/report.txt"

for style in stale decoy; do
  if HOME="$TMP/home" \
    PATH="$TMP/bin:/usr/bin:/bin" \
    TRNM_FIXTURE_METRICS_STYLE="$style" \
    OUT_DIR="$TMP/out/$style" \
    CONSENSUS_FAULT_MATRIX_OUT="$TMP/out/$style-report.txt" \
    CASE_FILTER=baseline \
    EXPECTED_CASES=1 \
    GATE_MODE=hard \
    ALLOW_FAIL=0 \
    "$GATE" >"$TMP/$style-gate.log" 2>&1; then
    echo "[FAIL] non-canonical $style metrics line was accepted" >&2
    exit 1
  fi

  grep -Eq '^result=FAIL reason=(missing_consensus_metrics|metrics_parse_error) ' \
    "$TMP/out/$style-report.txt"
  grep -q '^status=FAIL$' "$TMP/out/$style-report.txt"
done

echo "[PASS] consensus fault matrix accepts only the canonical finality_avg_ms-prefixed metrics line"
