#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
out=${TMPDIR:-/tmp}/trnm-g1-r4-safety-checkpoint-gate-evidence-v1.json
exec python3 "$root/scripts/ci/check_g1_r4_safety_checkpoint_v1.py" \
  --root "$root" \
  --evidence-out "$out" \
  "$@"
