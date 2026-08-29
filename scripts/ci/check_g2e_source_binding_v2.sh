#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=3cfc54ab3a2466b322e750a93654149ddffe6422

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD
python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2e/G2E_SOURCE_MANIFEST_V2.json').read_text())
a14=json.loads(Path('docs/evidence/g2c/G2C_AGENT_HANDOFF_V2.json').read_text())
assert m['schema']=='trnm-g2e-source-manifest-v2'
assert m['base_pr']==35
assert m['base_commit']=='3cfc54ab3a2466b322e750a93654149ddffe6422'
assert m['base_tree']=='b8b1d3ed31bab93b28efcea8c30b0916ca45b7e0'
assert m['a14_implementation_commit']==a14['head_commit']=='0eed454d2895b8b034ada2af6bf96006cb094475'
assert m['a14_base_sync_commit']=='3cfc54ab3a2466b322e750a93654149ddffe6422'
assert m['control_replay_commit']==a14['control_replay_commit']=='d1bbbb43d385dbadadb34710610a49e43c498863'
assert m['frozen_workflow_tree']==a14['frozen_workflow_tree']=='dc9157617e7d00750f878aad33ee9b5cae5d9d5d'
assert a14['status']=='MODULE_CLOSED_CANDIDATE'
workflows=sorted(p.name for p in Path('.github/workflows').glob('*.yml'))
assert len(workflows)==13, workflows
assert not any('exact-head' in name or name.startswith('trnm-g2') or name.startswith('trnm-g3-g5') for name in workflows), workflows
assert m['risk_root']=='8c9b246d0c94f0ffaf477c9385f296cc98f70951bed9316eb970efedb15d3a57'
for key in ('canonical_settlement_receipt','application_jmt_authority','governance_activation','poco_weight_eligible','g2e_exit','production_candidate'):
    assert m[key] is False, key
print('G2E source binding v2: exact strict-Clippy A14 publication, frozen workflow route and false authority guards')
PY
git diff --check
