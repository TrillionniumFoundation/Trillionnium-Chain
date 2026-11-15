set -euo pipefail
args=(--kind "$SOURCE_KIND" --expected-head "$EXPECTED_HEAD")
if test "$SOURCE_KIND" = prospective-merge; then
  args+=(--expected-base "$EXPECTED_BASE" --expected-merge "$EXPECTED_SOURCE")
fi
python3 scripts/ci/verify_ci_source.py "${args[@]}" --output "$W1_QROM_CURRENT_OUT/source-after.json" 2>&1 | tee "$W1_QROM_CURRENT_OUT/source-after.log"
