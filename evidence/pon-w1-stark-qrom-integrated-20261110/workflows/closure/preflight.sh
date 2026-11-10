set -euo pipefail
bash scripts/project-preflight.sh --audit 2>&1 | tee "$W1_CLOSURE_OUT/preflight.log"
