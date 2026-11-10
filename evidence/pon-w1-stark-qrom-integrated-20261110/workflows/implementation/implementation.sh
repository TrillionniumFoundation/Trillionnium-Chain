set -euo pipefail
python3 scripts/w1_qrom_current_implementation_audit.py --repo-root "$GITHUB_WORKSPACE" --output "$W1_QROM_CURRENT_OUT/implementation.json" 2>&1 | tee "$W1_QROM_CURRENT_OUT/implementation.log"
