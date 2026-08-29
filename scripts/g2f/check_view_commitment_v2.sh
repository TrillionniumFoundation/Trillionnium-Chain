#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
out=$(PYTHONDONTWRITEBYTECODE=1 python3 -B conformance/g2f/view_commitment_v2.py --self-test)
python3 - "$out" <<'PY'
import json,sys
v=json.loads(sys.argv[1])
assert v['schema']=='trnm-g2f-owner-view-commitment-evidence-v2'
assert v['positive']==4
assert len(v['negative'])==11
assert v['view_commitment']=='2fe37224cda2bd9c5bc28126aa257e1a74718b72086752447694ae89fd827dec'
assert len(v['consumed_commitment'])==64
for key in ('production_hsm_authority','canonical_jmt_authority','order_finality_authority','production_activation'):
    assert v[key] is False, key
print('G2F owner-issued immutable view commitment: ok')
PY
