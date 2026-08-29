#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
out=$(python3 tools/da-fullrep-model/fullrep_model.py --self-test)
python3 - "$out" <<'PY'
import json,sys
v=json.loads(sys.argv[1])
assert v['schema']=='trnm-da-fullrep-model-evidence-v1'
assert v['positive']==5
assert len(v['negative'])==6
assert v['candidate_only'] is True
assert v['network_authority'] is False
assert v['withholding']['outcome']=='withheld'
print('DA-FULLREP-V1 independent model: ok')
PY
