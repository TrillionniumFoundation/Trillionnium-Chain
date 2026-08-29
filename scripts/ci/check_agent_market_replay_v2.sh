#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"

python3 tools/agent-market-model/model.py --self-test >/tmp/trnm-agent-market-v1.json
python3 tools/agent-market-model/authority_extension_v2.py --self-test >/tmp/trnm-agent-market-v2.json

python3 - <<'PY'
import json
from pathlib import Path
v1=json.loads(Path('/tmp/trnm-agent-market-v1.json').read_text())
v2=json.loads(Path('/tmp/trnm-agent-market-v2.json').read_text())
source=json.loads(Path('docs/evidence/g2b/G2B_SOURCE_MANIFEST_V2.json').read_text())
handoff=json.loads(Path('docs/evidence/g2b/G2B_AGENT_HANDOFF_V2.json').read_text())
assert v1['schema']=='trnm-agent-market-model-evidence-v1'
assert v1['positive_transitions']>=10
assert len(v1['negative'])==7
assert v1['candidate_only'] is True
assert v1['global_state_authority'] is False
assert v2['schema']=='trnm-agent-market-authority-extension-evidence-v2'
assert v2['positive']==7
assert len(v2['negative'])==11
assert v2['controller_generation']==3
assert len(v2['state_commitment'])==64
assert v2['candidate_only'] is True
assert v2['cryptographic_authority'] is False
assert v2['global_state_authority'] is False
assert v2['production_activation'] is False
assert source['control_replay_commit']==handoff['control_replay_commit']=='d1bbbb43d385dbadadb34710610a49e43c498863'
assert source['frozen_workflow_tree']==handoff['frozen_workflow_tree']=='dc9157617e7d00750f878aad33ee9b5cae5d9d5d'
workflows=sorted(p.name for p in Path('.github/workflows').glob('*.yml'))
assert len(workflows)==13, workflows
assert not any('exact-head' in name or name.startswith('trnm-g2') or name.startswith('trnm-g3-g5') for name in workflows), workflows
for key in ('global_state_authority','agent_transaction_wire_accepted','g2b_exit','production_candidate'):
    assert source[key] is False, key
print('G2B replay v2: candidate lifecycle + authority attenuation + frozen exact-head route ok')
PY

git diff --check
