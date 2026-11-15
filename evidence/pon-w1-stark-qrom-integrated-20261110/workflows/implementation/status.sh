set -euo pipefail
w1_qrom_current_out="$RUNNER_TEMP/pon-w1-qrom-current-v2-$SOURCE_KIND-x64-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
mkdir -p "$w1_qrom_current_out"
python3 scripts/ci/w1_qrom_current_ci.py verify --repo-root "$GITHUB_WORKSPACE" --out "$w1_qrom_current_out" --kind "$SOURCE_KIND" --expected-source "$EXPECTED_SOURCE" --expected-head "$EXPECTED_HEAD" --expected-base "$EXPECTED_BASE" 2>&1 | tee "$w1_qrom_current_out/current-ci-status.log"
