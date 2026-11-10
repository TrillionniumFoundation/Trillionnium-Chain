set -euo pipefail
bash scripts/project-preflight.sh --audit 2>&1 | tee "$W1_QROM_CURRENT_OUT/preflight.log"
