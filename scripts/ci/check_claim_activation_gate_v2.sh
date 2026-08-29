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
assert v['synthetic_authorized_decision_root']=='ad1ae325fac3762af64ed01a444f807fb0b0ef5c00418fe8387d6635009b7028'
for key in ('real_claim_authorized','benchmark_results_present','public_testnet_ready','production_candidate','production_activation'):
    assert v[key] is False, key
print('G3-G5 claim and activation gate: fail-closed contract ok')
PY
