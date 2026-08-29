#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"

bash scripts/ci/check_g2f_source_binding_v2.sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s conformance/g2f -p 'test_*.py'
bash scripts/g2f/check_g2f_conformance.sh
bash scripts/g2f/check_view_commitment_v2.sh

git diff --check
