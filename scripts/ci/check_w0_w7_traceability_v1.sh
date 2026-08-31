#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"

# The old gate only checked a /tmp matrix and could pass while A08/A09 inputs
# were stale, malformed, or silently replaced.  The source-bound gate writes
# deterministic candidate evidence under docs/evidence/g2.0 and fails closed
# on dirty trees, tuple/blob drift, strict-parser failures, or missing IDs.
exec python3 tools/w0-w7-codegen/traceability_gate.py \
  --root "$root" \
  --manifest "$root/docs/evidence/g2.0/g20-source-manifest-v1.json" \
  --closure "$root/docs/evidence/g2.0/g20-w0-w7-closure-v1.json" \
  --evidence-index "$root/docs/evidence/g2.0/g20-evidence-index-v1.json"
