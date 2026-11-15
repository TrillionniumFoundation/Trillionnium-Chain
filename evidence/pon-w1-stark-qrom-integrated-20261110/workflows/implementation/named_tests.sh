set -euo pipefail
python3 scripts/ci/w1_qrom_current_ci.py named --repo-root "$GITHUB_WORKSPACE" --out "$W1_QROM_CURRENT_OUT" 2>&1 | tee "$W1_QROM_CURRENT_OUT/named-tests.log"
