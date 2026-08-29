#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=a21285eeb90b2f1adf027cbed8039e37a05e1f6d

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD

python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2d/G2D_SOURCE_MANIFEST_V2.json').read_text())
a12=json.loads(Path('docs/evidence/g2b/G2B_AGENT_HANDOFF_V2.json').read_text())
assert m['schema']=='trnm-g2d-source-manifest-v2'
assert m['base_pr']==33
assert m['base_commit']=='a21285eeb90b2f1adf027cbed8039e37a05e1f6d'
assert m['base_tree']=='a3dbf4c7c7b9a5b06643b75ad951af73b893087b'
assert m['a12_implementation_commit']==a12['head_commit']=='a6478b21dca97769d6e9acba611859a45c44a399'
assert a12['status']=='MODULE_CLOSED_CANDIDATE'
assert m['worker_counts']==[1,2,4,8]
for key in ('agent_transaction_wire_accepted','application_jmt_authority','settlement_authority','g2d_exit','production_candidate'):
    assert m[key] is False, key
print('G2D source binding v2: exact A12 candidate and false authority guards')
PY

git diff --check
