#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"

out=$(PYTHONDONTWRITEBYTECODE=1 python3 -B docs/development/agents/independent_package_review_gate_v1.py --self-test)
python3 - "$out" <<'PY'
import json,sys
value=json.loads(sys.argv[1])
assert value['schema']=='trnm-independent-package-review-gate-self-test-v1'
assert value['template']['valid'] is True
assert value['template']['real_review_present'] is False
assert value['synthetic_positive']==3
assert len(value['negative'])==24
assert len(value['synthetic_decision_root'])==64
for key in (
    'real_review_present','package_candidate_accepted','interface_candidate_accepted',
    'gate_exit_authorized','merge_authorized','release_authorized',
    'production_activation_authorized'
):
    assert value[key] is False, key
print('independent package review evaluator: deterministic candidate-only self-test ok')
PY

PYTHONDONTWRITEBYTECODE=1 python3 -B docs/development/agents/independent_package_review_gate_v1.py \
  --template docs/development/agents/INDEPENDENT_PACKAGE_REVIEW_DECISION_V1.json >/dev/null

python3 docs/development/agents/check_remaining_blocker_execution_v1.py
git diff --check
