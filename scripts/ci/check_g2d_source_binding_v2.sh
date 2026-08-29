#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
base=38d96ebc8d38903773ea8d164a6ca30fc6d46520

git cat-file -e "${base}^{commit}"
git merge-base --is-ancestor "$base" HEAD

python3 - <<'PY'
import json
from pathlib import Path
m=json.loads(Path('docs/evidence/g2d/G2D_SOURCE_MANIFEST_V2.json').read_text())
a12=json.loads(Path('docs/evidence/g2b/G2B_AGENT_HANDOFF_V2.json').read_text())
assert m['schema']=='trnm-g2d-source-manifest-v2'
assert m['base_pr']==33
assert m['base_commit']=='38d96ebc8d38903773ea8d164a6ca30fc6d46520'
assert m['base_tree']=='792030026aad6bde84591d9bbdaae84e1dc427a6'
assert m['a12_implementation_commit']==a12['head_commit']=='a6478b21dca97769d6e9acba611859a45c44a399'
assert m['control_replay_commit']=='53c0312cf0da46fc884025838aeb23e7d6ae0fe3'
assert a12['status']=='MODULE_CLOSED_CANDIDATE'
assert m['worker_counts']==[1,2,4,8]
assert Path('docs/development/agents/EXACT_HEAD_PACKAGE_REPLAY_POLICY_V1.md').is_file()
for path in (
    '.github/workflows/trnm-g2d-exact-head-v3.yml',
    '.github/workflows/trnm-g2d-execution-mvcc-fee-v2.yml',
):
    assert not Path(path).exists(), path
for key in ('agent_transaction_wire_accepted','application_jmt_authority','settlement_authority','g2d_exit','production_candidate'):
    assert m[key] is False, key
print('G2D source binding v2: exact A12 publication, frozen workflow route and false authority guards')
PY

git diff --check
