#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
out=$(PYTHONDONTWRITEBYTECODE=1 python3 -B tools/benchmark-contract/activation_gate_v2.py --self-test)
python3 - "$out" <<'PY'
import json,sys
v=json.loads(sys.argv[1])
assert v['schema']=='trnm-claim-activation-gate-evidence-v2'
assert v['positive']==3
assert len(v['negative'])==15
assert v['synthetic_authorized_decision_root']=='e7c04e43e24b42b9e3d305b00af83a1aee86343f5d0e3f287a030f0de1520414'
for key in ('real_claim_authorized','benchmark_results_present','public_testnet_ready','production_candidate','production_activation'):
    assert v[key] is False, key
print('G3-G5 claim and activation gate: fail-closed contract ok')
PY
