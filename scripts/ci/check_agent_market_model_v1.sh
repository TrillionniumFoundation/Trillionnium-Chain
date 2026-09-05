#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
out=$(python3 tools/agent-market-model/model.py --self-test)
python3 - "$out" <<'PY'
import json,sys
v=json.loads(sys.argv[1])
assert v['schema']=='trnm-agent-market-model-evidence-v1'
assert v['positive_transitions']>=10
assert len(v['negative'])==7
assert v['refunded']>=0
assert v['candidate_only'] is True
assert v['global_state_authority'] is False
print('agent-market independent model: ok')
PY
