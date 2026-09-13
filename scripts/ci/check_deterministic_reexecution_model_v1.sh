#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
out=$(python3 tools/verification-model/deterministic_reexecution.py --self-test)
python3 - "$out" <<'PY'
import json,sys
v=json.loads(sys.argv[1])
assert v['schema']=='trnm-deterministic-reexecution-evidence-v1'
assert v['positive']==['ResultFinal','ResultRejected','ResultFinal']
assert len(v['negative'])==9
assert v['candidate_only'] is True
assert v['global_profile_enabled'] is False
assert v['settlement_authority'] is False
print('deterministic re-execution model: ok')
PY
