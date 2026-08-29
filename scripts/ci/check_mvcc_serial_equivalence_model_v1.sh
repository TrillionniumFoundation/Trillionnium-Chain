#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
out=$(python3 tools/mvcc-serial-model/model.py --self-test)
python3 - "$out" <<'PY'
import json,sys
v=json.loads(sys.argv[1])
assert v['schema']=='trnm-mvcc-serial-equivalence-evidence-v1'
assert v['runs']==32*4*4
assert v['worker_counts']==[1,2,4,8]
assert len(v['negative'])==4
assert v['reexecutions']>0
assert v['candidate_only'] is True
assert v['jmt_authority'] is False
assert v['settlement_authority'] is False
print('MVCC serial-equivalence model: ok')
PY
