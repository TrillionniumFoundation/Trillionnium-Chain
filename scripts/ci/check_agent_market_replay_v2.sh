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
print('G2B replay v2: candidate lifecycle + authority attenuation model ok')
PY

git diff --check
