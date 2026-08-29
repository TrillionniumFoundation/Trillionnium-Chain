#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=f7619e4e6b626546225d66f52b83184ec3c21a0d

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD
python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2d/G2D_SOURCE_MANIFEST_V2.json').read_text())
a12=json.loads(Path('docs/evidence/g2b/G2B_AGENT_HANDOFF_V2.json').read_text())
assert m['schema']=='trnm-g2d-source-manifest-v2'
assert m['base_pr']==33
assert m['base_commit']=='f7619e4e6b626546225d66f52b83184ec3c21a0d'
assert m['base_tree']=='ef306af5df44b98d9f7389f0364a27c236c2e2c8'
assert m['a12_implementation_commit']==a12['head_commit']=='a6478b21dca97769d6e9acba611859a45c44a399'
assert m['control_replay_commit']==a12['control_replay_commit']=='d1bbbb43d385dbadadb34710610a49e43c498863'
assert m['frozen_workflow_tree']==a12['frozen_workflow_tree']=='dc9157617e7d00750f878aad33ee9b5cae5d9d5d'
assert a12['status']=='MODULE_CLOSED_CANDIDATE'
assert m['worker_counts']==[1,2,4,8]
workflows=sorted(p.name for p in Path('.github/workflows').glob('*.yml'))
assert len(workflows)==13, workflows
assert not any('exact-head' in name or name.startswith('trnm-g2') or name.startswith('trnm-g3-g5') for name in workflows), workflows
for key in ('agent_transaction_wire_accepted','application_jmt_authority','settlement_authority','g2d_exit','production_candidate'):
    assert m[key] is False, key
print('G2D source binding v2: exact A12 publication, final frozen workflow route and false authority guards')
PY
git diff --check
