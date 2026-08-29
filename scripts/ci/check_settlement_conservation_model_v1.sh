#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
out=$(python3 simulations/economics/settlement_model.py --self-test)
python3 - "$out" <<'PY'
import json,sys
v=json.loads(sys.argv[1])
assert v['schema']=='trnm-settlement-conservation-evidence-v1'
assert set(v['outcomes'])=={'ResultFinal','ResultRejected','Cancelled','Expired'}
assert len(v['negative'])==8
assert v['multi_asset'] is True
assert v['candidate_only'] is True
assert v['poco_weight_eligible'] is False
assert v['jmt_authority'] is False
print('settlement conservation model: ok')
PY
