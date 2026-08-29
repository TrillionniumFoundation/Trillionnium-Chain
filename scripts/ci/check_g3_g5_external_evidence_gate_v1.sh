#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"

out=$(PYTHONDONTWRITEBYTECODE=1 python3 -B tools/benchmark-contract/external_evidence_gate_v1.py --self-test)
python3 - "$out" <<'PY'
import json,sys
value=json.loads(sys.argv[1])
assert value['schema']=='trnm-external-evidence-gate-self-test-v1'
assert value['template']['valid'] is True
assert value['template']['real_evidence_present'] is False
assert value['template']['claim_authorized'] is False
assert value['synthetic_positive']==2
assert len(value['negative'])==36
assert len(value['synthetic_decision_root'])==64
for key in (
    'real_evidence_present','real_claim_authorized','public_testnet_ready',
    'production_candidate','production_activation','release_ready'
):
    assert value[key] is False, key
print('G3-G5 external evidence evaluator: deterministic fail-closed self-test ok')
PY

PYTHONDONTWRITEBYTECODE=1 python3 -B tools/benchmark-contract/external_evidence_gate_v1.py \
  --template docs/evidence/g3-g5/EXTERNAL_EVIDENCE_CAMPAIGN_TEMPLATE_V1.json >/dev/null

bash scripts/ci/check_g3_g5_external_evidence_template_v1.sh
git diff --check
